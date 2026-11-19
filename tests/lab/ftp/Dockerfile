FROM ubuntu:24.04
# Retry: an Ubuntu mirror mid-sync can list a package it can't serve yet (404) for a few minutes.
RUN for i in 1 2 3 4 5; do apt-get update && apt-get install -y --no-install-recommends vsftpd xinetd && break; \
      [ "$i" = 5 ] && exit 1; echo "apt failed, retrying in 30s ($i/5)"; sleep 30; done \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/run/vsftpd/empty /srv/ftp/backups
COPY vsftpd.conf /etc/vsftpd.conf
COPY xinetd-ftp /etc/xinetd.d/ftp
COPY files/ /srv/ftp/
RUN chown -R root:root /srv/ftp && chmod -R a+rX /srv/ftp
EXPOSE 21 30000-30009
# xinetd hands each connection to its own vsftpd process. vsftpd's standalone listener
# (listen=YES) segfaulted now and then under nmap's parallel -sV/-sC probing in a container,
# taking the whole service down; with one process per connection a crash can't.
CMD ["xinetd", "-dontfork", "-stayalive"]
