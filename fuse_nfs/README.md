# fuse-nfs
This is a fuse driver that can mount an NFS export. The advantage of this script compared to the normal way is that it autamatically sends the right uid and gid to the server to get access to as many files as possible. It is also able to mount an arbitrary file handle including file system root file handles found by nfs-analyze.

# Installation
1. install fuse3-dev
    ```
    sudo apt install libfuse3-dev
    ```
2. edit /etc/fuse.conf: uncomment line user_allow_other

# Usage
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

When running this program, always provide exactly one of the options --manual-fh or --export to specify the export root.

By default only read operations are allowed. If you need to make changes to the server, use --allow-write.