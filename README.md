
## Bridge over SSH
Bridge two virtual interfaces over SSH, using tuntap driver.

## Usage: brssh [SSH-OPTIONS]... user@hostname

- brssh client can be configured by editing /etc/brssh/client.cfg.
- brssh server can be configured by editing /etc/brssh/server.cfg.

## Overview
    brssh client, create a local tuntap interface and spawn a brssh server via ssh.
    brssh server also create a tuntap interface on remote server.
    The SSH connection is used to forward packets between client and server.
