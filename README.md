# Multi-tenant stack installer

One-shot installer for:

- Postgres + Adminer
- FastAPI API
- Nginx web frontend
- Caddy reverse proxy
- Multi-tenant DB structure with sections + items UI

Run on a fresh Ubuntu server:

```bash
sudo ./install_stack.sh
```
Check services are running:

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
```

Reload the service:
```bash
systemctl daemon-reload
```

Restart the service:
```bash
systemctl restart stack
```