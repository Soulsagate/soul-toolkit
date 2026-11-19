FROM ubuntu:24.04
# Retry: an Ubuntu mirror mid-sync can list a package it can't serve yet (404) for a few minutes.
RUN for i in 1 2 3 4 5; do apt-get update && apt-get install -y --no-install-recommends samba && break; \
      [ "$i" = 5 ] && exit 1; echo "apt failed, retrying in 30s ($i/5)"; sleep 30; done \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /srv/public && chmod 755 /srv/public
COPY smb.conf /etc/samba/smb.conf
COPY files/ /srv/public/
EXPOSE 139 445
CMD ["smbd", "--foreground", "--no-process-group", "--debug-stdout"]
