# nfs-analyze
This script prints details about an NFS server and detects some potential misconfigurations which are highlighted in red.
It is based on a modified version of pynfs.

WARNING: this script leaves traces in logs and the rmtab on the server.

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

# Checks
The script performs the following checks:

## Supported protocols
This check shows all supported protocols reported by portmap.
If this doesn't show anything, the server might be configured to only support NFSv4 which doesn't need portmap.

## NFSv3 exports
This is an overview of all available NFSv3 exports, allowed clients, authentication methods and export file handles.
Only the authentication methods available to the current host are listed. Exports can be configured to allow different authentication methods for different hosts.
If nothing is shown, it could mean, that the server only supports NFSv4.

## Clients connected to the NFS server
This is an overview of all clients connected to the server.
This list may be inaccurate for the following reasons:
- NFSv4 clients are not shown
- If clients do not unmount the export properly, they will remain in the list even if they are not connected anymore
- If clients skip the mount protocol and communicate with NFS directly, they will not be listed
- Windows does not list any clients

## NFS versions supported by the server
This check shows if NFS version 3, 4.0, 4.1 and 4.2 are supported. Earlier versions are not supported.

If no version is supported, there could be multiple reasons:
- The server only supports old NFS versions
- The server only supports NFSv4 but on a port that is not 2049
- The server is not an NFS server

This check check takes a long time because the script has to wait some time between each connection attempt.
Otherwise the server might return an error that the session is still open.
The delay between connection attempts can be set using the --delay option. The default value of 1000ms appears to be effective for Linux and Windows.
Disable this check when scanning many hosts and version information is not needed using the --skip-version-check option in order to speed up the process.

## Windows file handle signing
If an NFSv3 file handle looks like one from a Windows server, it checks if the last 10 bytes are 0 or not in order to determine if file handle signing is enabled.

## Escape
If the file handle looks like one from a Linux server, it tries to list the root directory of the file system of each export.

This only works if all of the following conditions are met:
- The server uses Linux
- The export does not have the option subtree_check set in /etc/exports
- The export is stored on an ext, xfs or btrfs file system

If this check reports a successful escape, check the directory listing to see if this escape would give an attacker access to files that are not accessible otherwise.
If the directory listing contains the same entries that the export itself contains, the export is already the root of the file system and the escape has no effect.

If the escape was sucessful, the check tries to read /etc/shadow using two methods:
1. use uid and gid 0 -> works if no_root_squash is enabled
2. if gid of /etc/shadow is not 0, use that gid -> works on Suse and Debian based systems

The /etc/shadow can only be read if the export is on the same partition where the operating system is installed.


## no_root_squash
WARNING: This creates a directory in each export and deletes it immediately afterwards. For this reason it has to be manually enabled using --cehck-no-root-squash


This check only works if the export allows AUTH_SYS and if it is writable.
It creates a directory owned by root and checks if the creation is successful.

## Overview of files available via NFSv4
This check is useful if the server doesn't support NFSv3 and the first check doesn't show any exports