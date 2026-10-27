# soul-lab: a deliberately vulnerable box for testing

A small "CTF box" built from standard Ubuntu packages, so you can try `toolkit recon` (and
develop modules) without touching anything you don't own. All services answer on one IP,
**172.29.99.10**, on a private Docker network. Nothing is published on your host's ports.

```bash
docker compose -f tests/lab/docker-compose.yml up -d --build   # first build takes a few minutes
toolkit recon 172.29.99.10
docker compose -f tests/lab/docker-compose.yml down
```

`pytest tests/test_lab.py` does the same automatically (it is skipped when Docker isn't
available; `SOUL_LAB_KEEP=1` leaves the lab running afterwards).

## What's on it

| Port | Service | The weakness |
|---|---|---|
| 21 | vsftpd | anonymous login, files in the root |
| 80 | nginx | asking by IP redirects to `lab.thm`; a `dev.lab.thm` vhost that nothing links to |
| 8080 | nginx | the app is served from its git checkout: `/.git` is readable (with a credential in its history), `robots.txt`, `/admin`, `/backup` |
| 139 / 445 | Samba | a null session lists the shares; `public` is guest-readable |
| 111 / 2049 / 20048 | nfs-ganesha | `/srv/nfs` exported read-only to everyone, `no_root_squash` |

Each service runs in its own container (`ftp/`, `web/`, `smb/`, `nfs/`); they share the
network namespace of a tiny `box` container so they look like one machine.

## Requirements and notes

- **Linux host.** Container IPs on a Docker network are reachable from the host on Linux. Docker
  Desktop (macOS / Windows) doesn't route to them; run the toolkit inside a container on the
  `soul-lab_lab` network instead.
- **NFS needs a host kernel of 6.6 or newer.** nfs-ganesha (a userspace NFS server - no kernel
  `nfsd` module needed) exports a tmpfs, and tmpfs only supports NFS file handles since Linux 6.6.
  On older kernels the other services still work.
- **Subnet clash?** If `172.29.99.0/24` is already used on your machine, change the subnet and
  `ipv4_address` in `docker-compose.yml` (and `TARGET` in `tests/test_lab.py`).
- The credentials and keys in the lab are fake and only exist inside these containers.
