This repository contains two tools, `nfs_analyze` and `fuse_nfs` that are released along with our [blog post](https://www.hvs-consulting.de/TODO) on the NFS protocol from a pentester's perspective.

These tools are designed for and tested on Linux. 
To install, first make sure libfuse3-dev is installed. 
For example, on Kali you can run 

~~~
sudo apt install libfuse3-dev
~~~

to install the dependency.

# nfs-analyze
This script prints details about an NFS server and detects some potential misconfigurations which are highlighted in red.
It is based on a [modified version of pynfs](https://github.com/hvs-consulting/pynfs).

**WARNING**: *This script leaves traces in logs and the rmtab on the server.*

```
usage: nfs-analyze.py [-h] [--check-no-root-squash] [--delay DELAY] [--skip-version-check] [--no-color] [--no-ping] [--ping-timeout PING_TIMEOUT] [--charset CHARSET] target

positional arguments:
  target                Target host, IP address or hostname

options:
  -h, --help            show this help message and exit
  --check-no-root-squash
                        Test if no_root_squash is enabled on the server which can be used for privilege escalation on clients. WARNING: THIS WRITES DATA ON THE SERVER (default: False)
  --delay DELAY         Number of milliseconds to wait between connections. If this value is too low, connections might fail (default: 1000)
  --skip-version-check  Skip version check to speed up the test (default: False)
  --no-color            Disable colored output (default: False)
  --no-ping             Do not ping clients reported by mount (default: False)
  --ping-timeout PING_TIMEOUT
                        Number of seconds before a ping times out (default: 1)
  --charset CHARSET     charset used by the server (default: utf-8)
```

The script performs the following checks:

### Supported protocols
This check shows all supported protocols reported by portmap.
If this doesn't show anything, the server might be configured to only support NFSv4 which doesn't need portmap.

### NFSv3 exports
This is an overview of all available NFSv3 exports, allowed clients, authentication methods and export file handles.
Only the authentication methods available to the current host are listed. Exports can be configured to allow different authentication methods for different hosts.
If nothing is shown, it could mean, that the server only supports NFSv4.

### Clients connected to the NFS server
This is an overview of all clients connected to the server.
This list may be inaccurate for the following reasons:
- NFSv4 clients are not shown
- If clients do not unmount the export properly, they will remain in the list even if they are not connected anymore
- If clients skip the mount protocol and communicate with NFS directly, they will not be listed
- The Windows NFS server implementation does not list any clients

### NFS versions supported by the server
This check shows if NFS version 3, 4.0, 4.1 and 4.2 are supported. Earlier NFS versions are not supported by this script.

If no version is reported, there could be multiple reasons:
- The server only supports old NFS versions
- The server only supports NFSv4 but on a port that is not 2049
- The server is not an NFS server

This check check takes a long time because the script has to wait some time between each connection attempt.
Otherwise the server might return an error that the session is still open.
The delay between connection attempts can be set using the `--delay` option. The default value of 1000ms appears to be effective for Linux and Windows.
Disable this check when scanning many hosts and version information is not needed using the `--skip-version-check` option in order to speed up the process.

### Windows file handle signing
If an NFSv3 file handle looks like one from a Windows server, it checks if the last 10 bytes are 0 or not in order to determine if file handle signing is enabled.

### Escape
If the file handle looks like one from a Linux server, it tries to list the root directory of the file system of each export.

This only works if all of the following conditions are met:
- The server uses Linux
- The export does not have the option `subtree_check` set in `/etc/exports`
- The export is stored on an `ext`, `xfs` or `btrfs` file system

If this check reports a successful escape, check the directory listing to see if this escape would give an attacker access to files that are not accessible otherwise.
If the directory listing contains the same entries that the export itself contains, the export is already the root of the file system and the escape has no effect.

If the escape was sucessful, the check tries to read `/etc/shadow` using two methods:
1. use uid and gid 0 -> works if `no_root_squash` is set
2. if gid of `/etc/shadow` is not 0, use that gid -> works on SuSE and Debian based systems

The `/etc/shadow` can only be read if the export is on the same partition where the operating system is installed.

### no_root_squash
**WARNING:** *This creates a directory in each export and deletes it immediately afterwards. For this reason it has to be manually enabled using `--check-no-root-squash`*

This check only works if the export allows `AUTH_SYS` and if it is writable.
It creates a directory owned by root and checks if the creation is successful.

### Overview of files available via NFSv4
This check is useful if the server doesn't support NFSv3 and the first check doesn't show any exports

![nfs_analyze](img/nfs_analyze.png)

# fuse-nfs
This is a fuse driver that can mount an NFS export. The advantage of this script compared to the normal way is that it autamatically sends the right uid and gid to the server to get access to as many files as possible. It is also able to mount an arbitrary file handle including file system root file handles found by nfs-analyze.

## Required setup
Edit `/etc/fuse.conf` and uncomment the line `user_allow_other`

## Usage
```
usage: fuse-nfs.py [-h] (--export EXPORT | --manual-fh MANUAL_FH) [--fake-uid] [--fake-uid-allow-root] [--allow-write] [--remote-symlinks] [--unprivileged-port]
                   [--debug] [--debug-fuse]
                   mountpoint host

positional arguments:
  mountpoint            Where to mount the file system
  host                  IP address of the host

options:
  -h, --help            show this help message and exit
  --export EXPORT       Path of export directory
  --manual-fh MANUAL_FH
                        Set a root file handle manually as a hex string
  --fake-uid            Fake UID to access more files
  --fake-uid-allow-root
                        Enable if no_root_squash is enabled on the export
  --allow-write         Allow writing
  --remote-symlinks     Follow symlinks on the server, not the client
  --unprivileged-port   Connect from a port >1024
  --debug               Enable debugging output
  --debug-fuse          Enable FUSE debugging output
```

When running this program, always provide exactly one of the options `--manual-fh` or `--export` to specify the export root.

By default only read operations are allowed. If you need to make changes to the server, use `--allow-write`.
