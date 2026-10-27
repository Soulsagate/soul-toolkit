FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends vsftpd && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /var/run/vsftpd/empty /srv/ftp/backups
COPY vsftpd.conf /etc/vsftpd.conf
COPY files/ /srv/ftp/
RUN chown -R root:root /srv/ftp && chmod -R a+rX /srv/ftp
EXPOSE 21 30000-30009
CMD ["vsftpd", "/etc/vsftpd.conf"]
