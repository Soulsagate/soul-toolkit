FROM ubuntu:24.04
# Retry: an Ubuntu mirror mid-sync can list a package it can't serve yet (404) for a few minutes.
RUN for i in 1 2 3 4 5; do apt-get update && apt-get install -y --no-install-recommends nfs-ganesha nfs-ganesha-vfs rpcbind && break; \
      [ "$i" = 5 ] && exit 1; echo "apt failed, retrying in 30s ($i/5)"; sleep 30; done \
 && rm -rf /var/lib/apt/lists/*
COPY ganesha.conf /etc/ganesha/ganesha.conf
COPY files/ /seed/
COPY start.sh /start.sh
EXPOSE 111 2049 20048
CMD ["sh", "/start.sh"]
