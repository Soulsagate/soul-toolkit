FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends vsftpd xinetd && rm -rf /var/lib/apt/lists/* \
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
