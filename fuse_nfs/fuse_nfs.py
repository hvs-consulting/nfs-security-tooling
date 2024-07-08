#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
fuse-nfs
This script is based on https://github.com/libfuse/pyfuse3/blob/master/examples/hello_asyncio.py
'''

import binascii
import sys

from argparse import ArgumentParser
import asyncio
import stat
import logging
import errno
import pyfuse3
import pyfuse3_asyncio
from collections import namedtuple
import datetime

import anfs

from anfs.protocol.rpc.messages import AUTH_SYS
from anfs.protocol.nfs3.messages import FILE_SYNC, GUARDED
from anfs.protocol.nfs3.client import NFSv3Client, NFSFileEntry
from anfs.protocol.nfs3.common.factory import NFS3ConnectionFactory

try:
    import faulthandler
except ImportError:
    pass
else:
    faulthandler.enable()

log = logging.getLogger(__name__)
pyfuse3_asyncio.enable()

DirCacheEntry = namedtuple("DirCacheEntry", ["name", "last_update", "items"])

class DirCache():
    def __init__(self):
        self.dirs = dict()
        self.next = 1
        self.INDEX_MASK = 0xFFFFFFFF
        self.DIR_MASK = 0xFFFFFFFF00000000
    
    async def exists(self, cookie):
        return self.get_dir(cookie) in self.dirs
    
    async def add_entry(self, name, last_update):
        self.dirs[next] = DirCacheEntry(name, last_update, [])
        self.next += 1
        return (self.next - 1) << 32

    async def delete_entry(self, cookie):
        del self.dirs[self.get_dir(cookie)]
    
    async def add_item(self, cookie, item):
        self.dirs[self.get_dir(cookie)].items.add(item)
    
    async def get_items(self, cookie):
        for element in self.dirs[self.get_dir(cookie)].items[self.get_index(cookie):]:
            yield element
    
    def next_cookie(self, cookie):
        return cookie+1
            
    def get_index(self, cookie):
        return cookie & self.INDEX_MASK
    
    def get_dir(self, cookie):
        return (cookie & self.DIR_MASK) >> 32

class DirEntry:
    def __init__(self, index, items):
        self.index = index
        self.items = items

class FuseNFS(pyfuse3.Operations):
    def __init__(self, host, export, mountpoint, id, fake_uid, fake_uid_allow_root, allow_write, manual_fh, remote_symlinks, unprivileged_port):
        super(FuseNFS, self).__init__()

        self.host = host
        self.export = export
        self.mountpoint = mountpoint
        self.fake_uid = fake_uid
        self.fake_uid_allow_root = fake_uid_allow_root
        self.allow_write = allow_write
        self.manual_fh = manual_fh
        self.remote_symlinks = remote_symlinks
        self.unprivileged_port = unprivileged_port
        self.uid, self.gid = [int(x) for x in id.split(":")]
        self.conn_factory = NFS3ConnectionFactory.from_url(f"nfs://{self.host}/?privport={0 if unprivileged_port else 1}")
        self.conn_factory.credential = AUTH_SYS(0, "b", self.uid, self.gid, [1001])
        self.mount = self.conn_factory.get_mount()
        self.root_fh = None
        self.nfs = None

        self.dir_cache_lock = asyncio.Lock()
        self.dir_cache = DirCache()

        self.dirs = dict()

        if self.export == None and self.manual_fh == None:
            raise RuntimeError("No export or file handle provided")

        sys.setrecursionlimit(100000)
        print(f"recursion limit: {sys.getrecursionlimit()}")
    
    async def init_mount(self):
        if self.root_fh == None:
            await self.mount_export()
    
    async def mount_export(self):
        if self.export != None:
            connect_result = await self.mount.connect()
            print(f"Connect result: {connect_result}")
            mount_result = await self.mount.mount(self.export)
            if mount_result[1] == None:
                self.root_fh = mount_result[0]
            else:
                print(f"Error mounting export: {str(mount_result[1])}")
                exit()
            print(self.root_fh)
        else:
            if self.manual_fh.startswith("0x"):
                self.manual_fh = self.manual_fh[2:]
            self.root_fh = binascii.unhexlify(self.manual_fh)
        self.nfs = self.conn_factory.get_client(self.root_fh)
        await self.nfs.connect()
        await self.nfs.null()
        self.connected = True
        await self.set_uid(self.uid, self.gid)
        asyncio.create_task(self.keepalive())

    async def set_uid(self, uid, gid, groups=[1001]):
        self.nfs.rpc.credential = AUTH_SYS(0, "b", uid, gid, groups)

    async def auto_set_uid(self, inode):
        if self.fake_uid:
            attrs = await self.getattr(inode)
            if attrs.st_uid != 0 or self.fake_uid_allow_root:
                await self.set_uid(attrs.st_uid, attrs.st_gid)
            elif attrs.st_uid == 0 and attrs.st_gid != 0:
                await self.set_uid(self.uid, attrs.st_gid)
        
    async def reset_uid(self):
        if self.fake_uid:
            await self.set_uid(self.uid, self.gid)
    
    async def getattr(self, inode, ctx=None):
        await self.init_mount()
        print(f"getattr {inode}")
        result = await self.nfs.getattr(ino_to_fh(inode))
        await self.handle_error(result, "getattr")
        return await self.convert_attributes(result[0])

    async def lookup(self, parent_inode, name, ctx=None):
        await self.init_mount()
        print(f"lookup {name}, ")
        if self.root_fh == None:
            print("lookup too early")
            raise pyfuse3.FUSEError(errno.ENOENT)
        lookup_res = await self.nfs.lookup(ino_to_fh(parent_inode), name.decode("utf-8"))
        if lookup_res[0] == False:
            print("error lookup")
            raise pyfuse3.FUSEError(errno.ENOENT)
        print(lookup_res)
        return await self.convert_attributes(lookup_res[0])

    async def opendir(self, inode, ctx):
        async with self.dir_cache_lock:
            await self.init_mount()
            await self.auto_set_uid(inode)
            print(f"opendir {inode}")

            dir_entry = DirEntry(0, [])

            async for entry, error in self.nfs.readdirplus(ino_to_fh(inode), dircount=4096, maxcount=262144):
                if error == None:
                    if entry.name != ".." and entry.name != ".":
                        dir_entry.items.append(entry)
                else:
                    print("readirplus error: ", end="")
                    print(error)
            
            print("opendir assign")
            self.dirs[inode] = dir_entry
            print("opendir done")

            await self.reset_uid()
            return inode
    
    async def releasedir(self, handle):
        print(f"releasedir {handle}")
        return

    async def readdir(self, ino, start_id, token):
        print(token)
        print(start_id)

        index = start_id
        for entry in self.dirs[ino].items[index:]:
            index += 1
            if pyfuse3.readdir_reply(token, entry.name.encode("utf-8"), await self.convert_attributes(entry), index) == False:
                self.dirs[ino].index = index
                return
    
    async def mkdir(self, parent_inode, name, mode, ctx):
        self.only_writable()
        await self.init_mount()
        await self.auto_set_uid(parent_inode)
        result = await self.nfs.mkdir(ino_to_fh(parent_inode), name.decode("utf-8"), mode & 0o7777)
        await self.handle_error(result, "mkdir")
        await self.reset_uid()
        return await self.convert_attributes(result[0])
    
    async def rmdir(self, parent_inode, name, ctx):
        self.only_writable()
        await self.init_mount()
        await self.auto_set_uid(parent_inode)
        result = await self.nfs.rmdir(ino_to_fh(parent_inode), name.decode("utf-8"))
        await self.handle_error(result, "rmdir")
        await self.reset_uid()
    
    async def rename(self, old_ino, old_name, new_ino, new_name, flags, ctx):
        self.only_writable()
        await self.init_mount()
        await self.auto_set_uid(new_ino)
        result = await self.nfs.rename(ino_to_fh(old_ino), old_name.decode("utf-8"), ino_to_fh(new_ino), new_name.decode("utf-8"))
        await self.handle_error(result, "rename")
        await self.reset_uid()
    
    async def access(self, ino, mode, ctx):
        return True

    async def open(self, inode, flags, ctx):
        return pyfuse3.FileInfo(fh=inode)

    async def read(self, ino, off, size):
        print(f"read: {ino}")
        await self.init_mount()
        await self.auto_set_uid(ino)
        result = await self.nfs.read(ino_to_fh(ino), off, size)
        await self.handle_error(result, "read")
        
        await self.reset_uid()
        return result[0]
    
    async def write(self, ino, off, buf):
        self.only_writable()
        print(f"write: {ino}")
        await self.init_mount()
        await self.auto_set_uid(ino)

        result = await self.nfs.write(ino_to_fh(ino), off, len(buf), buf, FILE_SYNC)
        if result[0] == False:
            print(f"write error: {result[1]}")
            await self.reset_uid()
            raise pyfuse3.FUSEError(errno.EIO)

        if result[0]["status"] != 0:
            print(f"write nfs error: {result[0]['status']}")
            await self.reset_uid()
            raise pyfuse3.FUSEError(errno.EIO)
        
        await self.reset_uid()
        return result[0]["resok"]["count"]

    async def create(self, parent_inode, name, mode, flags, ctx):
        print(f"create: {parent_inode}, {name}, {mode}")
        self.only_writable()
        await self.init_mount()
        await self.auto_set_uid(parent_inode)
        result = await self.nfs.create(ino_to_fh(parent_inode), name.decode("utf-8"), GUARDED, mode & 0o7777)
        await self.handle_error(result, "create")
        file_info = pyfuse3.FileInfo()
        file_info.fh = fh_to_ino(result[0].handle)
        return (file_info, convert_attributes(result[0]))

    async def unlink(self, parent_inode, name, ctx):
        print(f"unlink: {parent_inode}, {name}")
        self.only_writable()
        await self.init_mount()
        await self.auto_set_uid(parent_inode)

        result = await self.nfs.remove(ino_to_fh(parent_inode), name.decode("utf-8"))
        await self.handle_error(result, "unlink")

    async def setattr(self, inode, attr, fields, fh, ctx):
        print(f"setattr: {inode}, {attr.st_mode}")
        self.only_writable()
        await self.init_mount()
        await self.auto_set_uid(inode)

        new_atime = fuse_to_nfs_timestamp(attr.st_atime_ns) if fields.update_atime else None
        new_mtime = fuse_to_nfs_timestamp(attr.st_mtime_ns) if fields.update_atime else None
        new_mode = attr.st_mode & 0o7777 if fields.update_mode else None
        new_uid = attr.st_uid if fields.update_uid else None
        new_gid = attr.st_gid if fields.update_gid else None
        new_size = attr.st_size if fields.update_size else None

        result = await self.nfs.setattr(ino_to_fh(inode), new_mode, new_uid, new_gid, new_size)
        await self.handle_error(result, "setattr")
        await self.reset_uid()
        return await self.getattr(inode, ctx)
    
    async def readlink(self, inode, ctx):
        await self.init_mount()
        await self.auto_set_uid(inode)

        result = await self.nfs.readlink(ino_to_fh(inode))
        await self.handle_error(result, "readlink")

        path = result[0]
        if self.remote_symlinks and path[0] == '/':
            path = self.mountpoint + "/" + path
        
        return path.encode("utf-8")

    async def symlink(self, parent_inode, name, target, ctx):
        print(f"symlink: {parent_inode}: {name} -> {target}")
        self.only_writable()
        await self.init_mount()
        await self.auto_set_uid(parent_inode)

        result = await self.nfs.symlink(ino_to_fh(parent_inode), name.decode(), target.decode())
        await self.handle_error(result, "symlink")

        await self.reset_uid()
        return await self.lookup(parent_inode, name)
    
    async def mknod(self, parent_inode, name, mode, rdev, ctx):
        self.only_writable()
        await self.init_mount()
        await self.auto_set_uid(parent_inode)
        print(f"mknod {rdev}")
        result = await self.nfs.mknod(ino_to_fh(parent_inode), name.decode("utf-8"), fuse_to_nfs_type(mode), mode & 0o777, spec_major = rdev >> 8, spec_minor = rdev & 0xFF)
        print(result)
        await self.handle_error(result, "mknod")
        await self.reset_uid()
        #return await self.convert_attributes(result[0])
        return await self.lookup(parent_inode, name)

    async def convert_attributes(self, entry: NFSFileEntry):
        attrs = pyfuse3.EntryAttributes()

        mode = entry.mode

        if mode != None and self.fake_uid:
            if self.fake_uid_allow_root:
                mode |= mode >> 3 | mode >> 6
            else:
                if entry.uid != 0:
                    mode |= mode >> 6
                if entry.gid != 0:
                    mode |= (mode >> 3) & 0o007

        if entry.type != None:
            attrs.st_mode = file_types[entry.type] | mode
        if entry.handle != None:
            attrs.st_ino = fh_to_ino(entry.handle)
        if entry.uid != None:
            attrs.st_uid = entry.uid
        if entry.gid != None:
            attrs.st_gid = entry.gid
        if entry.nlink != None:
            attrs.st_nlink = entry.nlink
        if entry.size != None:
            attrs.st_size = entry.size
        if entry.atime != None:
            attrs.st_atime_ns = nfs_to_fuse_timestamp(entry.atime)
        if entry.ctime != None:
            attrs.st_ctime_ns = nfs_to_fuse_timestamp(entry.ctime)
        if entry.mtime != None:
            attrs.st_mtime_ns = nfs_to_fuse_timestamp(entry.mtime)

        return attrs
    
    async def handle_error(self, result, name):
        if result[0] == False:
            print(f"{name} error: {result[1]}")
            await self.reset_uid()
            raise pyfuse3.FUSEError(errno.EIO)
        
        if type(result[0]) == dict and "status" in result[0] and result[0]["status"] != 0:
            print(f"{name} nfs error {result[0]['status']}")
            await self.reset_uid()
            raise pyfuse3.FUSEError(errno.EIO)

    def only_writable(self):
        if not self.allow_write:
            raise pyfuse3.FUSEError(errno.ENOTSUP)
    
    async def keepalive(self):
        while True:
            await asyncio.sleep(60)
            await self.nfs.null()
    
def ino_to_fh(ino):
    return ino - 1

def fh_to_ino(fh):
    return fh + 1


class X:
    def __init__(self):
        self.a = None
        self.b = None

file_types = [0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFBLK, stat.S_IFCHR, stat.S_IFLNK, stat.S_IFSOCK, stat.S_IFIFO]

def fuse_to_nfs_type(fuse_type):
    return file_types.index(fuse_type & 0xF000)

def nfs_to_fuse_timestamp(timestamp: datetime.datetime):
    return int(datetime.datetime.timestamp(timestamp) * 1000000000)

def fuse_to_nfs_timestamp(timestamp: int):
    return datetime.datetime.fromtimestamp(timestamp / 1000000000)

def convert_attributes(entry: NFSFileEntry):
    attrs = pyfuse3.EntryAttributes()
    attrs.st_mode = file_types[entry.type] | entry.mode
    attrs.st_ino = fh_to_ino(entry.handle)
    attrs.st_uid = entry.uid
    attrs.st_gid = entry.gid
    attrs.st_nlink = entry.nlink
    attrs.st_size = entry.size
    attrs.st_atime_ns = nfs_to_fuse_timestamp(entry.atime)
    attrs.st_ctime_ns = nfs_to_fuse_timestamp(entry.ctime)
    attrs.st_mtime_ns = nfs_to_fuse_timestamp(entry.mtime)

    return attrs

def init_logging(debug=False):
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d %(threadName)s: '
                                  '[%(name)s] %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root_logger = logging.getLogger()
    if debug:
        handler.setLevel(logging.DEBUG)
        root_logger.setLevel(logging.DEBUG)
    else:
        handler.setLevel(logging.INFO)
        root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)

def parse_args():
    '''Parse command line'''

    parser = ArgumentParser()

    fh_group = parser.add_mutually_exclusive_group(required=True)
    id_group = parser.add_mutually_exclusive_group(required=False)

    parser.add_argument('mountpoint', type=str,
                        help='Where to mount the file system')
    parser.add_argument('host', type=str,
                        help='IP address of the host')
    fh_group.add_argument('--export', type=str,
                        help='Path of export directory')
    fh_group.add_argument('--manual-fh', type=str,
                        help='Set a root file handle manually as a hex string')
    id_group.add_argument('--uid', type=str,
                        help='Manualy set UID and GID number, format UID:GID', default="1000:1000")
    id_group.add_argument('--fake-uid', action='store_true', default=False,
                        help='Automatically fake UID and GID to access more files')
    parser.add_argument('--fake-uid-allow-root', action='store_true', default=False,
                        help='Enable if no_root_squash is enabled on the export')
    parser.add_argument('--allow-write', action='store_true', default=False,
                        help='Allow writing')
    parser.add_argument('--remote-symlinks', action='store_true', default=False,
                        help='Follow symlinks on the server, not the client')
    parser.add_argument('--unprivileged-port', action='store_true', default=False,
                        help='Connect from a port >1024')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Enable debugging output')
    parser.add_argument('--debug-fuse', action='store_true', default=False,
                        help='Enable FUSE debugging output')
    return parser.parse_args()


def main():
    options = parse_args()
    init_logging(options.debug)

    fuse_nfs = FuseNFS(options.host, options.export, options.mountpoint, options.uid, options.fake_uid, options.fake_uid_allow_root, options.allow_write, options.manual_fh, options.remote_symlinks, options.unprivileged_port)
    fuse_options = set(pyfuse3.default_options)
    fuse_options.add('fsname=fuse_nfs')
    fuse_options.add('allow_other')
    fuse_options.add('allow_root')
    #fuse_options.add('auto_unmount')
    fuse_options.add('dev')
    fuse_options.add('suid')
    if options.debug_fuse:
        fuse_options.add('debug')
    pyfuse3.init(fuse_nfs, options.mountpoint, fuse_options)
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(pyfuse3.main())
    except:
        pyfuse3.close(unmount=False)
        raise
    finally:
        loop.close()

    pyfuse3.close()

if __name__ == '__main__':
    main()
