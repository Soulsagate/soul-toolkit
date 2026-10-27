#!/bin/sh
# /srv/nfs is a tmpfs (see docker-compose.yml): fill it, start rpcbind, then ganesha in the foreground.
set -e
cp -a /seed/. /srv/nfs/
mkdir -p /run/ganesha /var/lib/nfs/ganesha
rpcbind -w
exec ganesha.nfsd -F -L /dev/stdout -f /etc/ganesha/ganesha.conf
