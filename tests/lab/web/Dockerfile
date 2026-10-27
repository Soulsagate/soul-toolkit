FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends nginx-light git ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY nginx.conf /etc/nginx/sites-enabled/default
COPY site/ /var/www/
# A real git repository left in the web root, with a credential in its history (git-dumper bait).
RUN cd /var/www/app && git init -q -b master \
 && git -c user.name=dev -c user.email=dev@lab.thm add -A \
 && printf '<?php\n$db_user = "app";\n$db_pass = "Summer2026!";\n' > config.php \
 && git -c user.name=dev -c user.email=dev@lab.thm add config.php \
 && git -c user.name=dev -c user.email=dev@lab.thm commit -q -m "initial site + db config" \
 && git rm -q --cached config.php && rm config.php \
 && git -c user.name=dev -c user.email=dev@lab.thm commit -q -m "remove config.php from the repo"
EXPOSE 80 8080
CMD ["nginx", "-g", "daemon off;"]
