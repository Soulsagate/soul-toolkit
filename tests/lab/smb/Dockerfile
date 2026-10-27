FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends samba && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /srv/public && chmod 755 /srv/public
COPY smb.conf /etc/samba/smb.conf
COPY files/ /srv/public/
EXPOSE 139 445
CMD ["smbd", "--foreground", "--no-process-group", "--debug-stdout"]
