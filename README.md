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

## Server file layout after running `setup.sh`

The installer writes everything under `/opt/stack` (owned by the invoking user) and drops a systemd unit for lifecycle management. After the script completes, the key files live at:

```
/opt/stack
├── .env                          # Generated if missing; holds DB creds, JWT secret, ports
├── docker-compose.yml            # Orchestrates db, adminer, api, web, caddy services
├── Caddyfile                     # Reverse-proxies /api to FastAPI and the rest to nginx web
├── db/
│   └── init/                     # Postgres init + seed
│       ├── 001_init.sql
│       ├── 002_seed.sql
│       ├── 003_admin_column.sql
│       ├── 004_user_preferences.sql
│       └── 005_user_fields.sql
├── api/
│   ├── Dockerfile
│   └── app/                      # FastAPI app code
│       ├── main.py
│       ├── auth.py
│       ├── deps.py
│       ├── database.py
│       ├── rls.py
│       └── schemas.py
├── web/
│   ├── Dockerfile
│   ├── nginx.conf
│   ├── public/                   # HTML + CSS assets
│   │   ├── app.css
│   │   ├── index.html
│   │   ├── accounts.html
│   │   ├── account.html
│   │   ├── section.html
│   │   ├── item.html
│   │   ├── admin.html
│   │   ├── admin-add.html
│   │   ├── items-settings.html
│   │   ├── settings.html
│   │   └── customisation.html
│   └── js/                       # Front-end modules
│       ├── common.js
│       ├── api.js
│       ├── auth.js
│       ├── admin.js
│       ├── admin_add.js
│       ├── settings.js
│       ├── customisation.js
│       ├── account.js
│       ├── section.js
│       ├── items_settings.js
│       └── item.js
└── scripts/                      # Utility helpers
    ├── create_tenant.sh
    └── rotate_secret.sh

/etc/systemd/system/stack.service  # systemd unit that runs `docker compose up` in /opt/stack
```
