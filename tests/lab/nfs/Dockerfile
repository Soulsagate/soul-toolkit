FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends nfs-ganesha nfs-ganesha-vfs rpcbind \
 && rm -rf /var/lib/apt/lists/*
COPY ganesha.conf /etc/ganesha/ganesha.conf
COPY files/ /seed/
COPY start.sh /start.sh
EXPOSE 111 2049 20048
CMD ["sh", "/start.sh"]
