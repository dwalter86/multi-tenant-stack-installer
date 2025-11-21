#!/usr/bin/env bash
# One-shot installer: Postgres + Adminer(local) + FastAPI + Web (nginx) + Caddy (HTTP)
# Admin UI + shared header/footer/menu
# Account page (sections list + modal section creator + 3-dot menu).
# Section page (schema-driven items table + 3-dot menu + item modal + item detail page).
# Safe to re-run (idempotent).
set -euo pipefail

# --- helpers ---
if [ "${EUID:-$(id -u)}" -ne 0 ]; then SUDO="sudo"; else SUDO=""; fi
USER_ID="${SUDO_USER:-$(id -u)}"
GROUP_ID="$(id -g "$USER_ID" 2>/dev/null || id -g)"
aptx() { $SUDO apt-get -o Dpkg::Lock::Timeout=600 "$@"; }

STACK_DIR="/opt/stack"
DB_INIT_DIR="$STACK_DIR/db/init"
API_DIR="$STACK_DIR/api"
API_APP_DIR="$API_DIR/app"
WEB_DIR="$STACK_DIR/web"
WEB_PUBLIC_DIR="$WEB_DIR/public"
WEB_JS_DIR="$WEB_DIR/js"
SCRIPTS_DIR="$STACK_DIR/scripts"

$SUDO mkdir -p "$DB_INIT_DIR" "$SCRIPTS_DIR" "$API_APP_DIR" "$WEB_PUBLIC_DIR" "$WEB_JS_DIR"
$SUDO chown -R "$USER_ID:$GROUP_ID" "$STACK_DIR"
cd "$STACK_DIR"

echo "[1/7] Installing base packages…"
aptx update -y
aptx install -y ca-certificates curl gnupg openssl ufw

echo "[swap] Ensuring swap is available (to avoid OOM during build)…"
ensure_swap() {
  if swapon --noheadings | grep -q .; then
    return
  fi
  echo "No swap detected; creating /swapfile (2G)…"
  if ! $SUDO fallocate -l 2G /swapfile 2>/dev/null; then
    $SUDO dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none
  fi
  $SUDO chmod 600 /swapfile
  $SUDO mkswap /swapfile >/dev/null
  $SUDO swapon /swapfile
  if ! grep -q "^/swapfile" /etc/fstab; then
    echo "/swapfile none swap sw 0 0" | $SUDO tee -a /etc/fstab >/dev/null
  fi
}
ensure_swap

if ! command -v docker >/dev/null 2>&1; then
  echo "[2/7] Installing Docker…"
  $SUDO install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  $SUDO chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
  aptx update -y
  aptx install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  $SUDO systemctl enable --now docker
else
  echo "[2/7] Docker already installed."
fi

echo "[3/7] Creating .env (if missing)…"
if [ ! -f .env ]; then
  POSTGRES_PASSWORD_GEN=$(openssl rand -hex 16)
  JWT_SECRET_GEN=$(openssl rand -hex 32)
  cat > .env <<ENV
# ===== Core =====
POSTGRES_USER=stack
POSTGRES_PASSWORD=${POSTGRES_PASSWORD_GEN}
POSTGRES_DB=accounts

# Public entry (Caddy)
HTTP_PORT=80
HTTPS_PORT=443
DOMAIN=

# API security
API_IP_ALLOWLIST=
JWT_SECRET=${JWT_SECRET_GEN}
JWT_EXPIRE_MINUTES=120

# Adminer bound only to localhost
ADMINER_BIND=127.0.0.1
ADMINER_PORT=8080

# Initial admin (override by editing .env before run)
ADMIN_EMAIL=admin@admin.co
ADMIN_PASSWORD=password
ENV
fi
set -a; . ./.env; set +a

echo "[4/7] Writing compose + app files…"
cat > docker-compose.yml <<'YML'
services:
  db:
    image: postgres:16
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    volumes:
      - ./db/init:/docker-entrypoint-initdb.d:ro
      - dbdata:/var/lib/postgresql/data
    networks: [backend]

  adminer:
    image: adminer:4
    restart: unless-stopped
    ports:
      - "${ADMINER_BIND}:${ADMINER_PORT}:8080"
    depends_on: [db]
    networks: [backend]

  api:
    build: ./api
    restart: unless-stopped
    environment:
      DATABASE_URL: postgresql+psycopg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@db:5432/${POSTGRES_DB}
      JWT_SECRET: ${JWT_SECRET}
      JWT_EXPIRE_MINUTES: ${JWT_EXPIRE_MINUTES}
      API_IP_ALLOWLIST: ${API_IP_ALLOWLIST}
    depends_on: [db]
    networks: [backend]

  web:
    build: ./web
    restart: unless-stopped
    depends_on: [api]
    networks: [backend]

  caddy:
    image: caddy:2
    restart: unless-stopped
    ports:
      - "${HTTP_PORT}:80"
      - "${HTTPS_PORT}:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on: [api, web]
    networks: [backend]

networks:
  backend:
    driver: bridge

volumes:
  dbdata:
  caddy_data:
  caddy_config:
YML

cat > Caddyfile <<'CADDY'
:80 {
  handle /api* {
    reverse_proxy http://api:8000
  }
  handle {
    reverse_proxy http://web:80
  }
}
CADDY

# --- DB schema + seed ---
cat > "$DB_INIT_DIR/001_init.sql" <<'SQL'
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL DEFAULT '',
  user_type TEXT NOT NULL DEFAULT 'standard',
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  is_admin BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS memberships (
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'member',
  PRIMARY KEY (user_id, account_id)
);

-- Configurable sections/collections per account
CREATE TABLE IF NOT EXISTS sections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  slug TEXT NOT NULL,
  label TEXT NOT NULL,
  schema JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (account_id, slug)
);

-- Store the current account context in a GUC (as TEXT)
CREATE OR REPLACE FUNCTION set_current_account(a TEXT) RETURNS VOID AS $$
BEGIN
  PERFORM set_config('app.current_account', a, true);
END; $$ LANGUAGE plpgsql;
SQL

cat > "$DB_INIT_DIR/002_seed.sql" <<SQL
DO \$\$
DECLARE
  u_id uuid;
  a_id uuid;
  sch  text;
  pol_exists boolean;
BEGIN
  SELECT id INTO u_id FROM users WHERE email='${ADMIN_EMAIL}';
  IF u_id IS NULL THEN
    INSERT INTO users(email, name, user_type, password_hash, is_admin)
    VALUES ('${ADMIN_EMAIL}', 'Super Admin', 'super_admin', crypt('${ADMIN_PASSWORD}', gen_salt('bf', 12)), TRUE)
    RETURNING id INTO u_id;
  ELSE
    UPDATE users
    SET is_admin=TRUE,
        user_type='super_admin',
        name=COALESCE(NULLIF(name, ''), 'Super Admin')
    WHERE id=u_id;
  END IF;

  SELECT id INTO a_id FROM accounts WHERE name='Default company';
  IF a_id IS NULL THEN
    INSERT INTO accounts(name) VALUES ('Default company') RETURNING id INTO a_id;
  END IF;

  INSERT INTO memberships(user_id, account_id, role)
  VALUES (u_id, a_id, 'owner')
  ON CONFLICT (user_id, account_id) DO NOTHING;

  sch := 'tenant_' || replace(a_id::text, '-', '');
  EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', sch);

  -- Ensure items table exists with section support.
  EXECUTE format('CREATE TABLE IF NOT EXISTS %I.items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    section_slug TEXT NOT NULL DEFAULT ''default'',
    name TEXT NOT NULL,
    data JSONB NOT NULL DEFAULT ''{}'',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )', sch);

  -- For existing tables, backfill and enforce section_slug.
  EXECUTE format('ALTER TABLE %I.items ADD COLUMN IF NOT EXISTS section_slug TEXT', sch);
  EXECUTE format('UPDATE %I.items SET section_slug = ''default'' WHERE section_slug IS NULL', sch);
  EXECUTE format('ALTER TABLE %I.items ALTER COLUMN section_slug SET DEFAULT ''default''', sch);
  EXECUTE format('ALTER TABLE %I.items ALTER COLUMN section_slug SET NOT NULL', sch);

  EXECUTE format('ALTER TABLE %I.items ENABLE ROW LEVEL SECURITY', sch);

  SELECT EXISTS(
    SELECT 1 FROM pg_policies
    WHERE schemaname = sch AND tablename = 'items' AND policyname = 'items_tenant_policy'
  ) INTO pol_exists;

  IF NOT pol_exists THEN
    EXECUTE format(
      'CREATE POLICY items_tenant_policy ON %I.items
       USING ( current_setting(''app.current_account'')::uuid = %L )
       WITH CHECK ( current_setting(''app.current_account'')::uuid = %L )',
      sch, a_id::text, a_id::text
    );
  END IF;
END\$\$;
SQL

cat > "$DB_INIT_DIR/003_admin_column.sql" <<'SQL'
ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;
SQL

cat > "$DB_INIT_DIR/004_user_preferences.sql" <<'SQL'
CREATE TABLE IF NOT EXISTS user_preferences (
  user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  ui_labels JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION set_user_preferences_updated_at()
RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'user_preferences_updated_at'
  ) THEN
    CREATE TRIGGER user_preferences_updated_at
    BEFORE UPDATE ON user_preferences
    FOR EACH ROW EXECUTE PROCEDURE set_user_preferences_updated_at();
  END IF;
END;$$;
SQL

cat > "$DB_INIT_DIR/005_user_fields.sql" <<'SQL'
ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE IF EXISTS users ADD COLUMN IF NOT EXISTS user_type TEXT NOT NULL DEFAULT 'standard';

UPDATE users
SET user_type = CASE
  WHEN is_admin THEN 'super_admin'
  ELSE 'standard'
END
WHERE COALESCE(user_type, '') = '';
SQL

# --- API ---
cat > "$API_DIR/Dockerfile" <<'DOCKER'
FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    pydantic \
    email-validator \
    sqlalchemy \
    psycopg[binary] \
    python-jose[cryptography]
COPY app /app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
DOCKER

cat > "$API_APP_DIR/database.py" <<'PY'
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.environ.get("DATABASE_URL", "")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
PY

cat > "$API_APP_DIR/schemas.py" <<'PY'
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Literal

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class Preferences(BaseModel):
    accounts_label: str = "Home"
    sections_label: str = "Sections"
    items_label: str = "Items"

class PreferencesUpdate(BaseModel):
    accounts_label: Optional[str] = None
    sections_label: Optional[str] = None
    items_label: Optional[str] = None

class MeOut(BaseModel):
    id: str
    email: EmailStr
    name: str
    user_type: str
    is_admin: bool
    preferences: Preferences = Preferences()

class AccountOut(BaseModel):
    id: str
    name: str

class AccountCreate(BaseModel):
    name: str

class AccountUpdate(BaseModel):
    name: str

class ItemCreate(BaseModel):
    name: str
    data: dict = Field(default_factory=dict)

class ItemOut(BaseModel):
    id: str
    name: str
    data: dict

class ItemsPage(BaseModel):
    items: List[ItemOut]
    next: Optional[str]

class AdminUser(BaseModel):
    id: str
    email: EmailStr
    name: str
    user_type: str
    is_active: bool
    preferences: Optional[Preferences] = None

class CreateAdmin(BaseModel):
    email: EmailStr
    password: str
    name: str
    user_type: Literal["super_admin", "admin", "standard"] = "admin"
    accounts: List[str] = Field(default_factory=list)

class SectionBase(BaseModel):
    slug: str
    label: str
    schema: dict = Field(default_factory=dict)

class SectionCreate(SectionBase):
    pass

class SectionUpdate(BaseModel):
    label: str
    schema: dict = Field(default_factory=dict)

class SectionOut(SectionBase):
    id: str
PY

cat > "$API_APP_DIR/auth.py" <<'PY'
import os, datetime
from jose import jwt
from sqlalchemy import text
from database import SessionLocal

JWT_SECRET = os.environ.get("JWT_SECRET", "change-me")
JWT_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", 120))

def create_token(sub: str) -> str:
  now = datetime.datetime.utcnow()
  exp = now + datetime.timedelta(minutes=JWT_EXPIRE_MINUTES)
  return jwt.encode({"sub": sub, "exp": exp}, JWT_SECRET, algorithm="HS256")

def login_and_get_user(email: str, password: str):
  with SessionLocal() as db:
    row = db.execute(
      text("""SELECT id::text, is_active
              FROM users
              WHERE email=:e AND crypt(:p, password_hash) = password_hash
              LIMIT 1"""),
      {"e": email, "p": password}
    ).first()
    if not row or not row.is_active:
      return None
    return row.id

def memberships_for_user(user_id: str):
  with SessionLocal() as db:
    rows = db.execute(text("""
      SELECT a.id::text, a.name
      FROM memberships m JOIN accounts a ON a.id = m.account_id
      WHERE m.user_id = :u
      ORDER BY a.created_at DESC
    """), {"u": user_id}).all()
    return [{"id": r[0], "name": r[1]} for r in rows]
PY

cat > "$API_APP_DIR/deps.py" <<'PY'
import os
from fastapi import Header, HTTPException, status, Request, Depends
from jose import jwt, JWTError
from sqlalchemy import text
from database import SessionLocal

JWT_SECRET = os.environ.get("JWT_SECRET", "change-me")
API_IP_ALLOWLIST = [s.strip() for s in os.environ.get("API_IP_ALLOWLIST", "").split(",") if s.strip()]

async def ip_allowlist(request: Request):
  if not API_IP_ALLOWLIST:
    return
  if request.client.host not in API_IP_ALLOWLIST:
    raise HTTPException(status_code=403, detail="IP not allowed")

async def current_user(authorization: str = Header(default="")) -> str:
  if not authorization.startswith("Bearer "):
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
  token = authorization.split(" ", 1)[1]
  try:
    payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    return payload["sub"]
  except JWTError:
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

def _get_user_type(user_id: str) -> str:
  with SessionLocal() as db:
    row = db.execute(text("SELECT COALESCE(user_type, CASE WHEN is_admin THEN 'admin' ELSE 'standard' END) FROM users WHERE id=:u LIMIT 1"), {"u": user_id}).first()
    return row[0] if row else "standard"

async def require_admin(user_id: str = Depends(current_user)) -> dict:
  user_type = _get_user_type(user_id)
  if user_type not in ("admin", "super_admin"):
    raise HTTPException(status_code=403, detail="Admin only")
  return {"id": user_id, "user_type": user_type}

async def require_super_admin(user_id: str = Depends(current_user)) -> dict:
  user_type = _get_user_type(user_id)
  if user_type != "super_admin":
    raise HTTPException(status_code=403, detail="Super admin only")
  return {"id": user_id, "user_type": user_type}
PY

cat > "$API_APP_DIR/rls.py" <<'PY'
import json
from sqlalchemy import text
from database import SessionLocal

def set_current_account(account_id: str):
  # DB function accepts TEXT, so we bind as plain text
  return text("SELECT set_current_account(:a)").bindparams(a=account_id)

def _schema_name(account_id: str) -> str:
  return f"tenant_{account_id.replace('-', '')}"

def list_items(account_id: str, section: str, limit: int = 50, cursor: str | None = None):
  schema = _schema_name(account_id)
  where = "WHERE section_slug = :section"
  params: dict = {"limit": limit, "section": section}
  if cursor:
    where += " AND id > :cursor"
    params["cursor"] = cursor
  sql = f"""
  SELECT id::text, name, COALESCE(data, '{{}}'::jsonb)
  FROM {schema}.items
  {where}
  ORDER BY id
  LIMIT :limit
  """
  with SessionLocal() as db:
    db.execute(set_current_account(account_id))
    rows = db.execute(text(sql), params).all()
    return [{"id": r[0], "name": r[1], "data": r[2]} for r in rows]

def create_item(account_id: str, section: str, name: str, data: dict):
  schema = _schema_name(account_id)
  sql = f"""
  INSERT INTO {schema}.items (section_slug, name, data)
  VALUES (:s, :n, CAST(:d AS jsonb))
  RETURNING id::text, name, data
  """
  payload = json.dumps(data or {})
  with SessionLocal() as db:
    db.execute(set_current_account(account_id))
    row = db.execute(text(sql), {"s": section, "n": name, "d": payload}).first()
    db.commit()
    return {"id": row[0], "name": row[1], "data": row[2]}

def update_item(account_id: str, item_id: str, name: str | None, data: dict | None):
  schema = _schema_name(account_id)
  sets = []
  params: dict = {"id": item_id}
  if name is not None:
    sets.append("name = :n")
    params["n"] = name
  if data is not None:
    sets.append("data = CAST(:d AS jsonb)")
    params["d"] = json.dumps(data)
  if not sets:
    return None
  sql = f"""
  UPDATE {schema}.items
  SET {', '.join(sets)}
  WHERE id = :id
  RETURNING id::text, name, data
  """
  with SessionLocal() as db:
    db.execute(set_current_account(account_id))
    row = db.execute(text(sql), params).first()
    db.commit()
    if not row:
      return None
    return {"id": row[0], "name": row[1], "data": row[2]}

def delete_item(account_id: str, item_id: str):
  schema = _schema_name(account_id)
  sql = f"DELETE FROM {schema}.items WHERE id = :id"
  with SessionLocal() as db:
    db.execute(set_current_account(account_id))
    db.execute(text(sql), {"id": item_id})
    db.commit()

def get_item(account_id: str, item_id: str):
  schema = _schema_name(account_id)
  sql = f"""
  SELECT id::text, name, COALESCE(data, '{{}}'::jsonb), section_slug
  FROM {schema}.items
  WHERE id = :id
  LIMIT 1
  """
  with SessionLocal() as db:
    db.execute(set_current_account(account_id))
    row = db.execute(text(sql), {"id": item_id}).first()
    if not row:
      return None
    return {"id": row[0], "name": row[1], "data": row[2], "section_slug": row[3]}
PY

cat > "$API_APP_DIR/main.py" <<'PY'
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import json
from schemas import (
    LoginRequest,
    Token,
    MeOut,
    AccountOut,
    AccountCreate,
    AccountUpdate,
    ItemCreate,
    ItemOut,
    ItemsPage,
    AdminUser,
    CreateAdmin,
    SectionCreate,
    SectionUpdate,
    SectionOut,
    Preferences,
    PreferencesUpdate,
)
from auth import login_and_get_user, create_token, memberships_for_user
from deps import current_user, ip_allowlist, require_admin
import rls
from sqlalchemy import text
from database import SessionLocal

DEFAULT_LABELS: dict[str, str] = {
  "accounts_label": "Home",
  "sections_label": "Sections",
  "items_label": "Items",
}

def merge_labels(raw: dict | None) -> dict:
  merged = dict(DEFAULT_LABELS)
  if isinstance(raw, dict):
    for key, val in raw.items():
      if key in merged and isinstance(val, str) and val.strip():
        merged[key] = val.strip()
  return merged

def get_preferences(db, user_id: str) -> dict:
  row = db.execute(text("SELECT ui_labels FROM user_preferences WHERE user_id=:u LIMIT 1"), {"u": user_id}).first()
  return merge_labels(row[0] if row else None)

def save_preferences(db, user_id: str, labels: dict) -> dict:
  merged = merge_labels(labels)
  db.execute(text("""
    INSERT INTO user_preferences(user_id, ui_labels)
    VALUES (:u, CAST(:l AS jsonb))
    ON CONFLICT (user_id) DO UPDATE SET ui_labels = EXCLUDED.ui_labels
  """), {"u": user_id, "l": json.dumps(merged)})
  db.commit()
  return merged

app = FastAPI(title="Multi-tenant JSON API")
app.add_middleware(
  CORSMiddleware,
  allow_origins=["*"],
  allow_credentials=True,
  allow_methods=["*"],
  allow_headers=["*"]
)

@app.post("/api/login", response_model=Token, dependencies=[Depends(ip_allowlist)])
async def login(payload: LoginRequest):
  uid = login_and_get_user(payload.email, payload.password)
  if not uid:
    raise HTTPException(status_code=401, detail="Invalid credentials")
  return Token(access_token=create_token(uid))

@app.get("/api/me", response_model=MeOut, dependencies=[Depends(ip_allowlist)])
async def me(user_id: str = Depends(current_user)):
  with SessionLocal() as db:
    row = db.execute(text("""
      SELECT id::text,
             email,
             COALESCE(name, ''),
             COALESCE(user_type, CASE WHEN is_admin THEN 'admin' ELSE 'standard' END),
             is_admin
      FROM users
      WHERE id=:u
    """), {"u": user_id}).first()
    if not row:
      raise HTTPException(status_code=404, detail="User not found")
    prefs = get_preferences(db, user_id)
    user_type = row[3] or ("admin" if row[4] else "standard")
    is_admin_flag = user_type in ("admin", "super_admin") or bool(row[4])
    return MeOut(id=row[0], email=row[1], name=row[2], user_type=user_type, is_admin=is_admin_flag, preferences=Preferences(**prefs))

@app.get("/api/me/preferences", response_model=Preferences, dependencies=[Depends(ip_allowlist)])
async def read_preferences(user_id: str = Depends(current_user)):
  with SessionLocal() as db:
    prefs = get_preferences(db, user_id)
    return Preferences(**prefs)

@app.put("/api/me/preferences", response_model=Preferences, dependencies=[Depends(ip_allowlist)])
async def update_preferences(body: PreferencesUpdate, user_id: str = Depends(current_user)):
  updates: dict[str, str] = {}
  for field in ("accounts_label", "sections_label", "items_label"):
    val = getattr(body, field)
    if val is not None:
      cleaned = val.strip()
      if not cleaned:
        raise HTTPException(status_code=400, detail=f"{field.replace('_', ' ').title()} cannot be empty")
      updates[field] = cleaned

  with SessionLocal() as db:
    current = get_preferences(db, user_id)
    current.update(updates)
    merged = save_preferences(db, user_id, current)
    return Preferences(**merged)

@app.get("/api/me/accounts", response_model=list[AccountOut], dependencies=[Depends(ip_allowlist)])
async def my_accounts(user_id: str = Depends(current_user)):
  return memberships_for_user(user_id)

@app.post("/api/accounts", response_model=AccountOut, status_code=201, dependencies=[Depends(ip_allowlist)])
async def create_account(body: AccountCreate, user_id: str = Depends(current_user)):
  name = body.name.strip()
  if not name:
    raise HTTPException(status_code=400, detail="Name is required")

  with SessionLocal() as db:
    row = db.execute(
      text("INSERT INTO accounts(name) VALUES (:n) RETURNING id::text, name"),
      {"n": name}
    ).first()
    if not row:
      raise HTTPException(status_code=500, detail="Failed to create account")

    account_id = row[0]
    schema_name = f"tenant_{account_id.replace('-', '')}"

    db.execute(
      text("""
        INSERT INTO memberships(user_id, account_id, role)
        VALUES (:u, :a, 'owner')
        ON CONFLICT (user_id, account_id) DO NOTHING
      """),
      {"u": user_id, "a": account_id}
    )

    schema_sql = f"""
      DO $$
      DECLARE sch text := '{schema_name}';
      BEGIN
        EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', sch);
        EXECUTE format('CREATE TABLE IF NOT EXISTS %I.items (
          id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          section_slug TEXT NOT NULL DEFAULT ''default'',
          name TEXT NOT NULL,
          data JSONB NOT NULL DEFAULT ''{{}}'',
          created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )', sch);
        EXECUTE format('ALTER TABLE %I.items ADD COLUMN IF NOT EXISTS section_slug TEXT', sch);
        EXECUTE format('UPDATE %I.items SET section_slug = ''default'' WHERE section_slug IS NULL', sch);
        EXECUTE format('ALTER TABLE %I.items ALTER COLUMN section_slug SET DEFAULT ''default''', sch);
        EXECUTE format('ALTER TABLE %I.items ALTER COLUMN section_slug SET NOT NULL', sch);
        EXECUTE format('ALTER TABLE %I.items ENABLE ROW LEVEL SECURITY', sch);
        IF NOT EXISTS (
          SELECT 1 FROM pg_policies
          WHERE schemaname = sch AND tablename = 'items' AND policyname = 'items_tenant_policy'
        ) THEN
          EXECUTE format(
            'CREATE POLICY items_tenant_policy ON %I.items
             USING ( current_setting(''app.current_account'')::uuid = ''{account_id}'' )
             WITH CHECK ( current_setting(''app.current_account'')::uuid = ''{account_id}'' )',
            sch);
        END IF;
      END $$;
    """
    db.execute(text(schema_sql))
    db.commit()
    return AccountOut(id=row[0], name=row[1])

# --- Account management ---

@app.put("/api/accounts/{account_id}", response_model=AccountOut, dependencies=[Depends(ip_allowlist)])
async def update_account(account_id: str, body: AccountUpdate, user_id: str = Depends(current_user)):
  with SessionLocal() as db:
    row = db.execute(
      text("UPDATE accounts SET name=:n WHERE id=:a RETURNING id::text, name"),
      {"n": body.name, "a": account_id}
    ).first()
    if not row:
      raise HTTPException(status_code=404, detail="Account not found")
    db.commit()
    return AccountOut(id=row[0], name=row[1])

@app.delete("/api/accounts/{account_id}", dependencies=[Depends(ip_allowlist)])
async def delete_account(account_id: str, user_id: str = Depends(current_user)):
  schema_name = f"tenant_{account_id.replace('-', '')}"
  with SessionLocal() as db:
    # Drop per-tenant schema if present
    db.execute(text("""
      DO $$
      DECLARE sch text := :sch;
      BEGIN
        EXECUTE format('DROP SCHEMA IF EXISTS %I CASCADE', sch);
      END $$;
    """), {"sch": schema_name})
    result = db.execute(text("DELETE FROM accounts WHERE id=:a"), {"a": account_id})
    db.commit()
    if result.rowcount == 0:
      raise HTTPException(status_code=404, detail="Account not found")
  return {"ok": True}

# --- Sections API ---

@app.get("/api/accounts/{account_id}/sections", response_model=list[SectionOut], dependencies=[Depends(ip_allowlist)])
async def list_sections(account_id: str, user_id: str = Depends(current_user)):
  with SessionLocal() as db:
    rows = db.execute(text("""
      SELECT id::text, slug, label, COALESCE(schema, '{}'::jsonb)
      FROM sections
      WHERE account_id = :a
      ORDER BY created_at
    """), {"a": account_id}).all()
    return [SectionOut(id=r[0], slug=r[1], label=r[2], schema=r[3]) for r in rows]

@app.post("/api/accounts/{account_id}/sections", response_model=SectionOut, dependencies=[Depends(ip_allowlist)])
async def create_section(account_id: str, body: SectionCreate, user_id: str = Depends(current_user)):
  payload = json.dumps(body.schema or {})
  with SessionLocal() as db:
    row = db.execute(text("""
      INSERT INTO sections(account_id, slug, label, schema)
      VALUES (:a, :slug, :label, CAST(:schema AS jsonb))
      ON CONFLICT (account_id, slug) DO UPDATE
        SET label = EXCLUDED.label,
            schema = EXCLUDED.schema
      RETURNING id::text, slug, label, COALESCE(schema, '{}'::jsonb)
    """), {"a": account_id, "slug": body.slug, "label": body.label, "schema": payload}).first()
    db.commit()
    return SectionOut(id=row[0], slug=row[1], label=row[2], schema=row[3])

@app.get("/api/accounts/{account_id}/sections/{slug}", response_model=SectionOut, dependencies=[Depends(ip_allowlist)])
async def get_section(account_id: str, slug: str, user_id: str = Depends(current_user)):
  with SessionLocal() as db:
    row = db.execute(text("""
      SELECT id::text, slug, label, COALESCE(schema, '{}'::jsonb)
      FROM sections
      WHERE account_id = :a AND slug = :s
      LIMIT 1
    """), {"a": account_id, "s": slug}).first()
    if not row:
      raise HTTPException(status_code=404, detail="Section not found")
    return SectionOut(id=row[0], slug=row[1], label=row[2], schema=row[3])

@app.put("/api/accounts/{account_id}/sections/{slug}", response_model=SectionOut, dependencies=[Depends(ip_allowlist)])
async def update_section(account_id: str, slug: str, body: SectionUpdate, user_id: str = Depends(current_user)):
  payload = json.dumps(body.schema or {})
  with SessionLocal() as db:
    row = db.execute(text("""
      UPDATE sections
      SET label = :label,
          schema = CAST(:schema AS jsonb)
      WHERE account_id = :a AND slug = :s
      RETURNING id::text, slug, label, COALESCE(schema, '{}'::jsonb)
    """), {"a": account_id, "s": slug, "label": body.label, "schema": payload}).first()
    if not row:
      raise HTTPException(status_code=404, detail="Section not found")
    db.commit()
    return SectionOut(id=row[0], slug=row[1], label=row[2], schema=row[3])

@app.delete("/api/accounts/{account_id}/sections/{slug}", dependencies=[Depends(ip_allowlist)])
async def delete_section(account_id: str, slug: str, user_id: str = Depends(current_user)):
  schema_name = f"tenant_{account_id.replace('-', '')}"
  with SessionLocal() as db:
    # Ensure RLS context and delete items in this section for that account
    db.execute(rls.set_current_account(account_id))
    db.execute(text(f"DELETE FROM {schema_name}.items WHERE section_slug = :slug"), {"slug": slug})
    res = db.execute(text("DELETE FROM sections WHERE account_id = :a AND slug = :s"), {"a": account_id, "s": slug})
    db.commit()
    if res.rowcount == 0:
      raise HTTPException(status_code=404, detail="Section not found")
  return {"ok": True}

# --- Items API (default section + per-section) ---

@app.get("/api/accounts/{account_id}/items", response_model=ItemsPage, dependencies=[Depends(ip_allowlist)])
async def list_items_default(account_id: str, limit: int = Query(50, ge=1, le=200), cursor: Optional[str] = None, user_id: str = Depends(current_user)):
  items = rls.list_items(account_id, section="default", limit=limit, cursor=cursor)
  next_cursor = items[-1]["id"] if items and len(items) == limit else None
  return ItemsPage(items=items, next=next_cursor)

@app.post("/api/accounts/{account_id}/items", response_model=ItemOut, dependencies=[Depends(ip_allowlist)])
async def create_item_default(account_id: str, body: ItemCreate, user_id: str = Depends(current_user)):
  return rls.create_item(account_id, section="default", name=body.name, data=body.data)

@app.get("/api/accounts/{account_id}/items/{item_id}", response_model=ItemOut, dependencies=[Depends(ip_allowlist)])
async def get_item(account_id: str, item_id: str, user_id: str = Depends(current_user)):
  item = rls.get_item(account_id, item_id)
  if not item:
    raise HTTPException(status_code=404, detail="Item not found")
  return ItemOut(id=item["id"], name=item["name"], data=item["data"])

@app.put("/api/accounts/{account_id}/items/{item_id}", response_model=ItemOut, dependencies=[Depends(ip_allowlist)])
async def update_item(account_id: str, item_id: str, body: ItemCreate, user_id: str = Depends(current_user)):
  updated = rls.update_item(account_id, item_id, name=body.name, data=body.data)
  if not updated:
    raise HTTPException(status_code=404, detail="Item not found")
  return updated

@app.delete("/api/accounts/{account_id}/items/{item_id}", dependencies=[Depends(ip_allowlist)])
async def delete_item(account_id: str, item_id: str, user_id: str = Depends(current_user)):
  rls.delete_item(account_id, item_id)
  return {"ok": True}

@app.get("/api/accounts/{account_id}/sections/{slug}/items", response_model=ItemsPage, dependencies=[Depends(ip_allowlist)])
async def list_section_items(account_id: str, slug: str, limit: int = Query(50, ge=1, le=200), cursor: Optional[str] = None, user_id: str = Depends(current_user)):
  items = rls.list_items(account_id, section=slug, limit=limit, cursor=cursor)
  next_cursor = items[-1]["id"] if items and len(items) == limit else None
  return ItemsPage(items=items, next=next_cursor)

@app.post("/api/accounts/{account_id}/sections/{slug}/items", response_model=ItemOut, dependencies=[Depends(ip_allowlist)])
async def create_section_item(account_id: str, slug: str, body: ItemCreate, user_id: str = Depends(current_user)):
  return rls.create_item(account_id, section=slug, name=body.name, data=body.data)

# --- Admin API ---

@app.get("/api/admin/users", response_model=list[AdminUser], dependencies=[Depends(ip_allowlist)])
async def list_admin_users(admin_ctx = Depends(require_admin)):
  with SessionLocal() as db:
    rows = db.execute(text("""
      SELECT id::text,
             email,
             COALESCE(name, ''),
             COALESCE(user_type, CASE WHEN is_admin THEN 'admin' ELSE 'standard' END),
             is_active
      FROM users
      ORDER BY created_at DESC
    """)).all()
    include_prefs = admin_ctx.get("user_type") == "super_admin"
    result: list[AdminUser] = []
    for r in rows:
      prefs = get_preferences(db, r[0]) if include_prefs else None
      result.append(AdminUser(id=r[0], email=r[1], name=r[2], user_type=r[3], is_active=r[4], preferences=Preferences(**prefs) if prefs else None))
    return result

@app.get("/api/admin/all-accounts", response_model=list[AccountOut], dependencies=[Depends(ip_allowlist), Depends(require_admin)])
async def list_all_accounts():
  with SessionLocal() as db:
    rows = db.execute(text("SELECT id::text, name FROM accounts ORDER BY created_at DESC")).all()
    return [{"id": r[0], "name": r[1]} for r in rows]

@app.post("/api/admin/users", response_model=AdminUser, status_code=201, dependencies=[Depends(ip_allowlist)])
async def create_admin(body: CreateAdmin, admin_ctx = Depends(require_admin)):
  requester_type = admin_ctx.get("user_type", "standard")
  if body.user_type == "super_admin" and requester_type != "super_admin":
    raise HTTPException(status_code=403, detail="Only super admins can create super admins")

  is_admin_flag = body.user_type in ("admin", "super_admin")

  with SessionLocal() as db:
    row = db.execute(text("SELECT id FROM users WHERE email=:e"), {"e": body.email}).first()
    if row:
      raise HTTPException(status_code=409, detail="Email already exists")
    row = db.execute(
      text("""
        INSERT INTO users(email, name, user_type, password_hash, is_admin, is_active)
        VALUES (:e, :n, :t, crypt(:p, gen_salt('bf', 12)), :is_admin, TRUE)
        RETURNING id::text, email, name, user_type, is_active
      """),
      {"e": body.email, "n": body.name.strip(), "t": body.user_type, "p": body.password, "is_admin": is_admin_flag}
    ).first()
    new_id = row[0]
    if body.accounts:
      ids = list({a for a in body.accounts})
      db.execute(
        text("INSERT INTO memberships(user_id, account_id, role) SELECT :u, a.id, 'owner' FROM accounts a WHERE a.id = ANY(:ids::uuid[]) ON CONFLICT DO NOTHING"),
        {"u": new_id, "ids": ids}
      )
    # Inherit creator customisation settings by default
    try:
      creator_prefs = get_preferences(db, admin_ctx.get("id"))
      save_preferences(db, new_id, creator_prefs)
    except Exception:
      pass
    db.commit()
    prefs = get_preferences(db, new_id) if requester_type == "super_admin" else None
    return AdminUser(id=row[0], email=row[1], name=row[2], user_type=row[3], is_active=row[4], preferences=Preferences(**prefs) if prefs else None)
PY

# --- Web (nginx) ---
cat > "$WEB_DIR/Dockerfile" <<'DOCKER'
FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY public /usr/share/nginx/html
COPY js /usr/share/nginx/html/js
DOCKER

cat > "$WEB_DIR/nginx.conf" <<'NGINX'
server {
  listen 80;
  server_name _;
  root /usr/share/nginx/html;
  index index.html;

  location /api/ { proxy_pass http://api:8000/api/; }
  location /docs { proxy_pass http://api:8000/docs; }
  location /openapi.json { proxy_pass http://api:8000/openapi.json; }
  location /redoc { proxy_pass http://api:8000/redoc; }

  location / { try_files $uri $uri/ /index.html; }
}
NGINX

# --- Web assets (CSS + helpers) ---
cat > "$WEB_PUBLIC_DIR/app.css" <<'CSS'
:root { --fg:#222; --muted:#666; --bg:#fafafa; --card:#fff; --border:#e5e5e5; }
* { box-sizing: border-box; }
body { margin:0; font:16px/1.4 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Cantarell,Noto Sans,Arial,"Apple Color Emoji","Segoe UI Emoji"; color:var(--fg); background:var(--bg); }
header, footer { background:var(--card); border-bottom:1px solid var(--border); }
footer { border-top:1px solid var(--border); border-bottom:none; color:var(--muted); }
.container { max-width:960px; margin:0 auto; padding:16px; }
.brand { font-weight:600; }
.menu { display:flex; gap:8px; align-items:center; }
.menu a, .btn { text-decoration:none; color:var(--fg); border:1px solid var(--border); padding:6px 10px; border-radius:6px; background:#fff; cursor:pointer; }
.menu .pill { border:none; color:var(--muted); }
main.container { padding-top:24px; padding-bottom:24px; background:var(--card); border:1px solid var(--border); border-radius:10px; margin-top:16px; }
table { width:100%; border-collapse:collapse; }
th, td { padding:8px; border-bottom:1px solid var(--border); text-align:left; vertical-align:top; }
.actions { display:flex; justify-content:flex-end; margin:8px 0; gap:8px; }
.checkbox-grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(260px,1fr)); gap:8px; }
.small { color:var(--muted); font-size:.9em; }
input, textarea, select { width:100%; padding:8px; border:1px solid var(--border); border-radius:6px; }
label { display:block; }
.card { border:1px solid var(--border); border-radius:8px; padding:12px; background:#fff; }
.stacked-list { display:flex; flex-direction:column; gap:12px; margin-top:12px; }
.account-card { display:flex; justify-content:space-between; align-items:center; gap:12px; }
.account-card strong { font-size:1.05em; }
pre { background:#f4f4f4; padding:8px; border-radius:6px; overflow:auto; }

/* Account/Section header + 3-dot menu */
.account-header {
  display:flex;
  justify-content:space-between;
  align-items:flex-start;
  gap:12px;
  margin-bottom:12px;
}
.account-header-main {
  display:flex;
  align-items:flex-start;
  gap:8px;
}
.account-header-main h1 {
  margin:0;
}
.account-header-actions {
  position:relative;
}
.icon-btn {
  border:none;
  background:transparent;
  padding:4px 8px;
  cursor:pointer;
  border-radius:999px;
  font-size:20px;
  line-height:1;
}
.icon-btn:hover {
  background:rgba(0,0,0,0.05);
}

.dropdown-menu {
  position:absolute;
  right:0;
  top:100%;
  margin-top:4px;
  min-width:180px;
  background:#fff;
  border:1px solid var(--border);
  border-radius:8px;
  padding:4px 0;
  box-shadow:0 10px 30px rgba(0,0,0,0.12);
  z-index:20;
  display:none;
}
.dropdown-menu.open { display:block; }
.dropdown-menu button {
  width:100%;
  border:none;
  background:transparent;
  text-align:left;
  padding:8px 12px;
  font:inherit;
  cursor:pointer;
}
.dropdown-menu button:hover {
  background:#f5f5f5;
}
.dropdown-menu .danger {
  color:#b00020;
}

/* Modal */
.modal-backdrop {
  position:fixed;
  inset:0;
  background:rgba(0,0,0,0.35);
  display:flex;
  align-items:center;
  justify-content:center;
  z-index:30;
}
.modal {
  background:#fff;
  border-radius:10px;
  max-width:480px;
  width:100%;
  padding:16px;
  box-shadow:0 16px 40px rgba(0,0,0,0.18);
}
.modal h2 { margin-top:0; }
.modal-actions {
  margin-top:12px;
  display:flex;
  justify-content:flex-end;
  gap:8px;
}
.btn.primary {
  background:#222;
  color:#fff;
}
.btn.primary:hover {
  filter:brightness(0.95);
}
.btn.small {
  font-size:.85em;
  padding:4px 8px;
}
.hidden { display:none !important; }

.empty-state {
  margin-top:16px;
  text-align:center;
}
.empty-state p { margin-bottom:12px; }

/* Item table */
.table-wrapper {
  overflow-x:auto;
}
.tag {
  display:inline-block;
  padding:2px 6px;
  border-radius:999px;
  border:1px solid var(--border);
  font-size:.75rem;
  color:var(--muted);
}

/* Vertical properties table */
.properties-table th {
  width:30%;
  color:var(--muted);
  font-weight:500;
}
.properties-table td {
  word-break:break-word;
}

/* Key/value editor */
.kv-table input {
  width:100%;
}
.kv-remove-btn {
  border:none;
  background:transparent;
  cursor:pointer;
  font-size:18px;
  line-height:1;
}
.kv-remove-btn:hover {
  color:#b00020;
}
CSS

cat > "$WEB_JS_DIR/common.js" <<'JS'
export function getToken(){ return sessionStorage.getItem('token') || ''; }
export function setToken(t){ sessionStorage.setItem('token', t); }
export function logout(){ sessionStorage.removeItem('token'); window.location.replace('/'); }

export const DEFAULT_LABELS = {
  accounts_label: 'Home',
  sections_label: 'Sections',
  items_label: 'Items',
};

export function getLabels(user){
  const prefs = user?.preferences || {};
  return {
    accounts_label: (prefs.accounts_label || DEFAULT_LABELS.accounts_label).trim() || DEFAULT_LABELS.accounts_label,
    sections_label: (prefs.sections_label || DEFAULT_LABELS.sections_label).trim() || DEFAULT_LABELS.sections_label,
    items_label: (prefs.items_label || DEFAULT_LABELS.items_label).trim() || DEFAULT_LABELS.items_label,
  };
}

export async function api(path, opts={}){
  const headers = Object.assign({ 'Content-Type':'application/json' }, opts.headers||{});
  const token = getToken();
  if(token) headers.Authorization = 'Bearer '+token;
  const res = await fetch(path, Object.assign({}, opts, { headers }));
  if(!res.ok){
    const text = await res.text().catch(()=>res.statusText);
    throw new Error(text || ('HTTP '+res.status));
  }
  const ct = res.headers.get('content-type')||'';
  return ct.includes('application/json') ? res.json() : res.text();
}

export async function loadMeOrRedirect(){
  const token = getToken();
  if(!token){ window.location.replace('/'); return null; }
  try { return await api('/api/me'); }
  catch(e){ logout(); return null; }
}

export function renderShell(user){
  const labels = getLabels(user);
  const header = document.getElementById('site-header');
  const footer = document.getElementById('site-footer');
  if(header){
    header.innerHTML = `
      <div class="container" style="display:flex;justify-content:space-between;align-items:center;gap:12px;">
        <div class="brand">ADIGI One Platform</div>
        <nav class="menu">
          <span class="pill small">${user?.email||''}</span>
          <a href="/accounts.html">Home</a>
          ${user?.is_admin ? '<a href="/settings.html">Settings</a>' : ''}
          <a href="#" id="logoutBtn" class="btn">Logout</a>
        </nav>
      </div>`;
    const btn=document.getElementById('logoutBtn'); if(btn) btn.addEventListener('click',(e)=>{e.preventDefault(); logout();});
  }
  if(footer){
    const year=new Date().getFullYear();
    footer.innerHTML = `<div class="container small">&copy; ${year} ADIGI One Platform</div>`;
  }
}
JS

# --- Pages ---
cat > "$WEB_PUBLIC_DIR/index.html" <<'HTML'
<!doctype html><html><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login</title>
  <link rel="stylesheet" href="/app.css">
</head><body>
  <header id="site-header"></header>
  <main class="container">
    <h1>Login</h1>
    <form id="loginForm">
      <p><input type="email" id="email" placeholder="Email" required></p>
      <p><input type="password" id="password" placeholder="Password" required></p>
      <p><button type="submit" class="btn">Login</button></p>
    </form>
    <div id="msg" class="small"></div>
  </main>
  <script type="module" src="/js/auth.js"></script>
</body></html>
HTML

cat > "$WEB_PUBLIC_DIR/accounts.html" <<'HTML'
<!doctype html><html><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Accounts</title>
  <link rel="stylesheet" href="/app.css">
</head><body>
  <header id="site-header"></header>
  <main class="container">
    <div class="account-header">
      <div class="account-header-main">
        <h1 id="accountsHeading">Your Accounts</h1>
      </div>
      <div class="account-header-actions">
        <button id="accountsMenuButton" class="icon-btn" aria-haspopup="true" aria-expanded="false" aria-label="Account actions">⋯</button>
        <div id="accountsMenu" class="dropdown-menu">
          <button type="button" data-action="add-account" id="addAccountBtnLabel">Add account</button>
        </div>
      </div>
    </div>

    <section>
      <div id="accountsEmptyState" class="empty-state hidden">
        <p class="small" id="accountsEmptyCopy">You do not belong to any accounts yet.</p>
      </div>
      <div id="accountList" class="stacked-list"></div>
    </section>
  </main>
  <script type="module" src="/js/api.js"></script>
</body></html>
HTML

cat > "$WEB_PUBLIC_DIR/admin.html" <<'HTML'
<!doctype html><html><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Users</title>
  <link rel="stylesheet" href="/app.css">
</head><body>
  <header id="site-header"></header>
  <main class="container">
    <div class="account-header">
      <div class="account-header-main">
        <h1>Users</h1>
        <div class="small">Manage user access, roles, and customisations.</div>
      </div>
      <div class="account-header-actions">
        <a class="btn primary" href="/admin-add.html">Add user</a>
      </div>
    </div>

    <section>
      <div id="usersEmptyState" class="empty-state hidden">
        <p class="small">No users yet.</p>
        <p><a class="btn" href="/admin-add.html">Add user</a></p>
      </div>
      <div id="userList" class="stacked-list"></div>
    </section>

    <section class="card" style="margin-top:16px;">
      <h2 style="margin-top:0;">User types</h2>
      <ul>
        <li><strong>Super admin:</strong> Can access everything (all accounts, create/edit/remove accounts, manage all sections and items, manage all users with customisation settings, access all settings).</li>
        <li><strong>Admin:</strong> Can access allocated accounts, create/edit/remove accounts, sections, and items, create admin and user logins for accounts they manage, and user customisations inherit the creator’s settings. Access limited settings.</li>
        <li><strong>Standard user:</strong> Access allocated accounts, sections, and items only; no access to settings.</li>
      </ul>
      <p class="small">Customised label settings for users are only visible to super admins.</p>
    </section>
  </main>
  <script type="module" src="/js/admin.js"></script>
</body></html>
HTML

cat > "$WEB_PUBLIC_DIR/admin-add.html" <<'HTML'
<!doctype html><html><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Add user</title>
  <link rel="stylesheet" href="/app.css">
</head><body>
  <header id="site-header"></header>
  <main class="container">
    <h1>Add user</h1>
    <p class="small">Create a new platform user, choose their role, and assign the accounts they can access.</p>
    <form id="addForm" class="card" style="padding:16px;">
      <p><label>Full name<input type="text" id="name" placeholder="Name" required></label></p>
      <p><label>Email<input type="email" id="email" placeholder="Email" required></label></p>
      <p><label>Password<input type="password" id="password" placeholder="Password" required></label></p>
      <p><label>User type
        <select id="userType">
          <option value="super_admin">Super admin</option>
          <option value="admin">Admin</option>
          <option value="standard">Standard user</option>
        </select>
      </label></p>
      <h3>Grant access to accounts</h3>
      <p><label><input type="checkbox" id="selectAll"> Select all</label></p>
      <div id="acctGrid" class="checkbox-grid"></div>
      <p class="small">If none are selected, the user will be created without memberships.</p>
      <p class="small">Admins and super admins inherit your customisation settings when you create them.</p>
      <p><button type="submit" class="btn primary">Create user</button></p>
      <p id="msg" class="small"></p>
    </form>
    <p><a class="btn" href="/admin.html">Back to users</a></p>
  </main>
  <script type="module" src="/js/admin_add.js"></script>
</body></html>
HTML

cat > "$WEB_PUBLIC_DIR/settings.html" <<'HTML'
<!doctype html><html><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Settings</title>
  <link rel="stylesheet" href="/app.css">
</head><body>
  <header id="site-header"></header>
  <main class="container">
    <h1>Settings</h1>
    <p class="small">Choose a settings area to manage.</p>
    <div id="settingsList" class="stacked-list"></div>
  </main>
  <script type="module" src="/js/settings.js"></script>
</body></html>
HTML

cat > "$WEB_PUBLIC_DIR/customisation.html" <<'HTML'
<!doctype html><html><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Customisation</title>
  <link rel="stylesheet" href="/app.css">
</head><body>
  <header id="site-header"></header>
  <main class="container">
    <a class="btn" href="/settings.html">← Back to settings</a>
    <h1>Customisation</h1>
    <p class="small">Update the labels you see for key parts of the UI. Changes are saved to your user profile.</p>
    <form id="customisationForm" class="card" style="padding:16px;">
      <p><label>Accounts label<input type="text" id="accountsLabel" required></label></p>
      <p><label>Sections label<input type="text" id="sectionsLabel" required></label></p>
      <p><label>Items label<input type="text" id="itemsLabel" required></label></p>
      <div class="actions" style="justify-content:flex-start;">
        <button type="submit" class="btn primary">Save changes</button>
        <button type="button" class="btn" id="resetDefaults">Reset to defaults</button>
      </div>
      <p id="customisationMsg" class="small"></p>
    </form>
  </main>
  <script type="module" src="/js/customisation.js"></script>
</body></html>
HTML

# Account detail page (sections list + 3-dot menu + modal "Create section")
cat > "$WEB_PUBLIC_DIR/account.html" <<'HTML'
<!doctype html><html><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Account</title>
  <link rel="stylesheet" href="/app.css">
</head><body>
  <header id="site-header"></header>
  <main class="container">
    <div class="account-header">
      <div class="account-header-main">
        <a class="btn" href="/accounts.html">Back</a>
        <div>
          <h1 id="acctName">Account</h1>
        </div>
      </div>
      <div class="account-header-actions">
        <button id="accountMenuButton" class="icon-btn" aria-haspopup="true" aria-expanded="false" aria-label="Account actions">⋯</button>
        <div id="accountMenu" class="dropdown-menu">
          <button type="button" data-action="edit">Edit account</button>
          <button type="button" data-action="add-section">Add section</button>
          <button type="button" data-action="delete" class="danger">Delete account</button>
        </div>
      </div>
    </div>

    <section>
      <h2 id="sectionsHeading">Sections</h2>
      <div id="sectionList"></div>
      <div id="emptyState" class="empty-state hidden">
        <p class="small" id="sectionsEmptyCopy">No sections have been created for this account yet.</p>
        <button id="emptyCreateSectionBtn" class="btn">Create a section</button>
      </div>
    </section>

    <!-- Modal for creating a section -->
    <div id="sectionModal" class="modal-backdrop hidden">
      <div class="modal">
        <h2>Create section</h2>
        <form id="sectionForm">
          <p><label>Slug (no spaces)<input type="text" id="sectionSlug" required></label></p>
          <p><label id="sectionLabelPrompt">Label (display name)<input type="text" id="sectionLabel" required></label></p>
          <div class="modal-actions">
            <button type="button" class="btn" id="sectionCancel">Cancel</button>
            <button type="submit" class="btn primary">Save</button>
          </div>
        </form>
        <p id="sectionMsg" class="small"></p>
      </div>
    </div>
  </main>
  <script type="module" src="/js/account.js"></script>
</body></html>
HTML

# Section page (schema-driven items table + 3-dot menu + item modal)
cat > "$WEB_PUBLIC_DIR/section.html" <<'HTML'
<!doctype html><html><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Section</title>
  <link rel="stylesheet" href="/app.css">
</head><body>
  <header id="site-header"></header>
  <main class="container">
    <div class="account-header">
      <div class="account-header-main">
        <a class="btn" href="#" id="backLink">Back</a>
        <div>
          <h1 id="sectionTitle">Section</h1>
          <p class="small" id="sectionMeta"></p>
        </div>
      </div>
      <div class="account-header-actions">
        <button id="sectionMenuButton" class="icon-btn" aria-haspopup="true" aria-expanded="false" aria-label="Section actions">⋯</button>
        <div id="sectionMenu" class="dropdown-menu">
          <button type="button" data-action="edit" id="editSectionMenuLabel">Edit section</button>
          <button type="button" data-action="add-item" id="addItemMenuLabel">Add item</button>
          <button type="button" data-action="delete" class="danger" id="deleteSectionMenuLabel">Delete section</button>
        </div>
      </div>
    </div>

    <section class="card">
      <div class="actions" style="margin-top:0;margin-bottom:8px;justify-content:space-between;">
        <h2 style="margin:0;" id="itemsHeading">Items</h2>
        <button id="addItemButton" class="btn">Add item</button>
      </div>
      <div id="itemsEmptyState" class="empty-state hidden">
        <p class="small" id="itemsEmptyCopy">No items in this section yet.</p>
        <button id="emptyAddItemButton" class="btn">Add your first item</button>
      </div>
      <div id="itemsTableContainer" class="table-wrapper"></div>
    </section>

    <!-- Modal for creating an item -->
    <div id="itemModal" class="modal-backdrop hidden">
      <div class="modal">
        <h2 id="itemModalTitle">Add item</h2>
        <form id="itemForm">
          <p><label>Name<input type="text" id="itemName" required></label></p>

          <div id="schemaFieldsContainer" class="schema-fields hidden"></div>

          <div id="kvEditorContainer" class="kv-editor hidden">
            <p class="small">Define key/value pairs for this item's data.</p>
            <div class="table-wrapper">
              <table class="kv-table">
                <thead><tr><th>Key</th><th>Value</th><th></th></tr></thead>
                <tbody id="kvRows"></tbody>
              </table>
            </div>
            <div class="actions" style="justify-content:flex-start;margin-top:8px;">
              <button type="button" id="addKVRowBtn" class="btn small">Add row</button>
            </div>
          </div>

          <div class="modal-actions">
            <button type="button" class="btn" id="itemCancel">Cancel</button>
            <button type="submit" class="btn primary">Save</button>
          </div>
        </form>
        <p id="itemMsg" class="small"></p>
      </div>
    </div>
  </main>
  <script type="module" src="/js/section.js"></script>
</body></html>
HTML

# Item detail page (vertical layout)
cat > "$WEB_PUBLIC_DIR/item.html" <<'HTML'
<!doctype html><html><head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Item</title>
  <link rel="stylesheet" href="/app.css">
</head><body>
  <header id="site-header"></header>
  <main class="container">
    <div class="account-header">
      <div class="account-header-main">
        <a class="btn" href="#" id="backToSection">Back</a>
        <div>
          <h1 id="itemName">Item</h1>
          <p class="small" id="itemMeta"></p>
        </div>
      </div>
    </div>

    <section class="card">
      <div class="table-wrapper">
        <table class="properties-table">
          <tbody id="itemProperties"></tbody>
        </table>
      </div>
    </section>

    <section class="card">
      <details>
        <summary class="small">Raw JSON</summary>
        <pre id="itemRaw"></pre>
      </details>
    </section>
  </main>
  <script type="module" src="/js/item.js"></script>
</body></html>
HTML

# --- JS modules ---
cat > "$WEB_JS_DIR/auth.js" <<'JS'
import { setToken, renderShell } from './common.js';
renderShell(null);
const form = document.getElementById('loginForm');
const msg = document.getElementById('msg');
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  try {
    const res = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email, password})});
    if(!res.ok) throw new Error('Login failed');
    const data = await res.json();
    if(!data?.access_token) throw new Error('No token');
    setToken(data.access_token);
    window.location.replace('/accounts.html');
  } catch(err){ msg.textContent = err.message || 'Login failed'; }
});
JS

# Accounts listing
cat > "$WEB_JS_DIR/api.js" <<'JS'
import { loadMeOrRedirect, renderShell, api, getLabels } from './common.js';
(async () => {
  const me = await loadMeOrRedirect(); if(!me) return;
  renderShell(me);
  
  const labels = getLabels(me);
  const accountHeading = document.getElementById('accountsHeading');
  const emptyCopy = document.getElementById('accountsEmptyCopy');
  const addAccountBtnLabel = document.getElementById('addAccountBtnLabel');
  if(accountHeading){ accountHeading.textContent = labels.accounts_label; }
  if(emptyCopy){ emptyCopy.textContent = `You do not have any ${labels.accounts_label.toLowerCase()} yet.`; }
  if(addAccountBtnLabel){ addAccountBtnLabel.textContent = `Add ${labels.accounts_label}`; }
  document.title = labels.accounts_label;
  
  const listEl = document.getElementById('accountList');
  const emptyStateEl = document.getElementById('accountsEmptyState');
  const menuButton = document.getElementById('accountsMenuButton');
  const menu = document.getElementById('accountsMenu');

  function openMenu(){
    menu.classList.add('open');
    menuButton.setAttribute('aria-expanded', 'true');
    const handler = (ev) => {
      if(!menu.contains(ev.target) && ev.target !== menuButton){
        closeMenu();
      }
    };
    document.addEventListener('click', handler, { once:true });
  }

  function closeMenu(){
    menu.classList.remove('open');
    menuButton.setAttribute('aria-expanded', 'false');
  }

  menuButton.addEventListener('click', (e) => {
    e.stopPropagation();
    if(menu.classList.contains('open')) closeMenu(); else openMenu();
  });

  document.addEventListener('keydown', (e) => {
    if(e.key === 'Escape'){ closeMenu(); }
  });

  async function loadAccounts(){
    try {
      const accounts = await api('/api/me/accounts');
      if(!accounts.length){
        listEl.innerHTML = '';
        emptyStateEl.classList.remove('hidden');
        return;
      }
      emptyStateEl.classList.add('hidden');
      listEl.innerHTML = accounts.map(a => `
        <div class="card account-card">
          <div>
            <strong>${a.name}</strong>
            <div class="small"><code>${a.id}</code></div>
          </div>
          <div>
            <a class="btn" href="/account.html?id=${encodeURIComponent(a.id)}">Open</a>
          </div>
        </div>
      `).join('');
    } catch(e){
      listEl.innerHTML = `<p class="small">Failed to load accounts: ${e.message}</p>`;
      emptyStateEl.classList.add('hidden');
    }
  }

  menu.addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-action]');
    if(!btn) return;
    const action = btn.dataset.action;
    closeMenu();
    if(action === 'add-account'){
      const name = prompt('Account name');
      if(!name) return;
      const trimmed = name.trim();
      if(!trimmed) return;
      try {
        await api('/api/accounts', { method:'POST', body: JSON.stringify({ name: trimmed }) });
        await loadAccounts();
      } catch(err){
        alert(err.message || 'Failed to create account');
      }
    }
  });

  await loadAccounts();
})();
JS

cat > "$WEB_JS_DIR/admin.js" <<'JS'
import { loadMeOrRedirect, renderShell, api, DEFAULT_LABELS } from './common.js';

const TYPE_LABELS = {
  super_admin: 'Super admin',
  admin: 'Admin',
  standard: 'Standard user'
};

(async () => {
  const me = await loadMeOrRedirect(); if(!me) return;
  renderShell(me);
  if(!me.is_admin){ window.location.replace('/accounts.html'); return; }

  const list = document.getElementById('userList');
  const emptyState = document.getElementById('usersEmptyState');
  const showPreferences = me.user_type === 'super_admin';

  function renderPrefs(user){
    if(!showPreferences || !user.preferences) return '';
    const prefs = user.preferences;
    const changed = Object.entries(prefs).filter(([k,v]) => {
      const defaultVal = DEFAULT_LABELS[k] || '';
      return (v || '').trim() && v.trim() !== defaultVal;
    });
    if(!changed.length) return '<div class="small">Customised fields: none</div>';
    const items = changed.map(([k,v]) => `<li><strong>${k.replace('_',' ')}:</strong> ${v}</li>`).join('');
    return `<div class="small">Customised fields:<ul>${items}</ul></div>`;
  }

  try {
    const users = await api('/api/admin/users');
    if(!users.length){
      list.innerHTML = '';
      emptyState.classList.remove('hidden');
      return;
    }
    emptyState.classList.add('hidden');
    list.innerHTML = users.map(u => {
      const typeLabel = TYPE_LABELS[u.user_type] || u.user_type;
      const status = u.is_active ? 'Active' : 'Disabled';
      const prefs = renderPrefs(u);
      const name = u.name?.trim() || u.email;
      return `
        <div class="card account-card">
          <div>
            <strong>${name}</strong>
            <div class="small">${u.email}</div>
            <div class="small">${typeLabel} • ${status}</div>
            ${prefs}
          </div>
          <div>
            <span class="pill small">${typeLabel}</span>
          </div>
        </div>
      `;
    }).join('');
  } catch(e){
    list.innerHTML = `<p class="small">Failed to load users: ${e.message}</p>`;
    emptyState.classList.add('hidden');
  }
})();
JS

cat > "$WEB_JS_DIR/admin_add.js" <<'JS'
import { loadMeOrRedirect, renderShell, api } from './common.js';
(async () => {
  const me = await loadMeOrRedirect(); if(!me) return;
  renderShell(me);
  if(!me.is_admin){ window.location.replace('/accounts.html'); return; }

  const grid = document.getElementById('acctGrid');
  const selectAll = document.getElementById('selectAll');
  const msg = document.getElementById('msg');
  const form = document.getElementById('addForm');
  const userType = document.getElementById('userType');
  const nameInput = document.getElementById('name');

  if(me.user_type !== 'super_admin'){
    const superOpt = userType.querySelector('option[value="super_admin"]');
    if(superOpt) superOpt.disabled = true;
    if(userType.value === 'super_admin') userType.value = 'admin';
  }
  
  try {
    const accounts = await api('/api/admin/all-accounts');
    grid.innerHTML = accounts.map(a => `
      <label><input type="checkbox" value="${a.id}"> ${a.name} <span class="small"><code>${a.id}</code></span></label>
    `).join('');
  } catch(e){
    grid.innerHTML = `<p class="small">Failed to load accounts: ${e.message}</p>`;
  }

  selectAll.addEventListener('change', () => {
    grid.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = selectAll.checked);
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    msg.textContent = 'Creating…';
    const name = nameInput.value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value;
    const selected = Array.from(grid.querySelectorAll('input[type="checkbox"]:checked')).map(cb => cb.value);
    const role = userType.value;
    if(!name){ msg.textContent = 'Name is required'; return; }
    try {
      await api('/api/admin/users', { method:'POST', body: JSON.stringify({ name, email, password, user_type: role, accounts: selected }) });
      msg.textContent = 'User created successfully.';
      form.reset();
      selectAll.checked = false;
      if(me.user_type !== 'super_admin'){ userType.value = 'admin'; }
    } catch(err){
      msg.textContent = err.message || 'Failed to create user';
    }
  });
})();
JS

cat > "$WEB_JS_DIR/settings.js" <<'JS'
import { loadMeOrRedirect, renderShell } from './common.js';

(async () => {
  const me = await loadMeOrRedirect(); if(!me) return;
  renderShell(me);
  if(!me.is_admin){ window.location.replace('/accounts.html'); return; }

  const list = document.getElementById('settingsList');
  const sections = [
    { key:'users', label:'Users', description:'Manage user roles, access, and settings.', href:'/admin.html' },
    { key:'customisation', label:'Customisation', description:'Rename UI labels for accounts, sections, and items for your user.', href:'/customisation.html' },
  ];

  list.innerHTML = sections.map(section => `
    <div class="card account-card">
      <div>
        <strong>${section.label}</strong>
        <div class="small">${section.description}</div>
      </div>
      <div><a class="btn" href="${section.href}">Open</a></div>
    </div>
  `).join('');
})();
JS

cat > "$WEB_JS_DIR/customisation.js" <<'JS'
import { loadMeOrRedirect, renderShell, api, getLabels, DEFAULT_LABELS } from './common.js';

(async () => {
  const me = await loadMeOrRedirect(); if(!me) return;
  renderShell(me);
  if(!me.is_admin){ window.location.replace('/accounts.html'); return; }

  const form = document.getElementById('customisationForm');
  const msg = document.getElementById('customisationMsg');
  const accountsInput = document.getElementById('accountsLabel');
  const sectionsInput = document.getElementById('sectionsLabel');
  const itemsInput = document.getElementById('itemsLabel');
  const resetBtn = document.getElementById('resetDefaults');

  const labels = getLabels(me);
  document.title = 'Customisation';
  accountsInput.value = labels.accounts_label;
  sectionsInput.value = labels.sections_label;
  itemsInput.value = labels.items_label;

  async function save(payload){
    msg.textContent = 'Saving…';
    try{
      const res = await api('/api/me/preferences', { method:'PUT', body: JSON.stringify(payload) });
      me.preferences = res;
      renderShell(me);
      msg.textContent = 'Saved.';
    }catch(e){
      msg.textContent = e.message || 'Failed to save preferences';
    }
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    await save({
      accounts_label: accountsInput.value.trim(),
      sections_label: sectionsInput.value.trim(),
      items_label: itemsInput.value.trim(),
    });
  });

  if(resetBtn){
    resetBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      accountsInput.value = DEFAULT_LABELS.accounts_label;
      sectionsInput.value = DEFAULT_LABELS.sections_label;
      itemsInput.value = DEFAULT_LABELS.items_label;
      await save(DEFAULT_LABELS);
    });
  }
})();
JS

# Account details logic (sections list + menu + modal)
cat > "$WEB_JS_DIR/account.js" <<'JS'
import { loadMeOrRedirect, renderShell, api, getLabels } from './common.js';

function qs(name){
  const m = new URLSearchParams(location.search).get(name);
  return m && decodeURIComponent(m);
}

function slugify(val){
  const s = (val || '').toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return s || 'section';
}

(async () => {
  const me = await loadMeOrRedirect(); if(!me) return;
  renderShell(me);
  const labels = getLabels(me);

  const accountId = qs('id');
  if(!accountId){
    document.body.innerHTML = '<main class="container"><p>Missing account id.</p></main>';
    return;
  }

  const acctNameEl = document.getElementById('acctName');
  const sectionListEl = document.getElementById('sectionList');
  const emptyStateEl = document.getElementById('emptyState');
  const emptyCreateBtn = document.getElementById('emptyCreateSectionBtn');

  const sectionsHeading = document.getElementById('sectionsHeading');
  const sectionsEmptyCopy = document.getElementById('sectionsEmptyCopy');
  const sectionModalTitle = document.getElementById('sectionModalTitle');
  const sectionLabelPrompt = document.getElementById('sectionLabelPrompt');

  if(sectionsHeading){ sectionsHeading.textContent = labels.sections_label; }
  if(sectionsEmptyCopy){ sectionsEmptyCopy.textContent = `No ${labels.sections_label.toLowerCase()} have been created for this account yet.`; }
  if(sectionModalTitle){ sectionModalTitle.textContent = `Create ${labels.sections_label}`; }
  if(sectionLabelPrompt){ sectionLabelPrompt.firstChild.textContent = `${labels.sections_label} name`;
    const input = sectionLabelPrompt.querySelector('input');
    if(input) input.placeholder = `${labels.sections_label} name`;
  }

  const modal = document.getElementById('sectionModal');
  const sectionForm = document.getElementById('sectionForm');
  const sectionMsg = document.getElementById('sectionMsg');
  const sectionSlugInput = document.getElementById('sectionSlug');
  const sectionLabelInput = document.getElementById('sectionLabel');
  const sectionCancel = document.getElementById('sectionCancel');

  const menuButton = document.getElementById('accountMenuButton');
  const menu = document.getElementById('accountMenu');
  const addSectionMenuBtn = menu ? menu.querySelector('button[data-action="add-section"]') : null;

  if(emptyCreateBtn){ emptyCreateBtn.textContent = `Create a ${labels.sections_label}`; }
  if(addSectionMenuBtn){ addSectionMenuBtn.textContent = `Add ${labels.sections_label}`; }

  let accountName = `Account ${accountId}`;

  try {
    const myAccounts = await api('/api/me/accounts');
    const match = myAccounts.find(a => a.id === accountId);
    if(match){
      accountName = match.name;
      acctNameEl.textContent = match.name;
    } else {
      acctNameEl.textContent = `Account ${accountId}`;
    }
  } catch {
    acctNameEl.textContent = `Account ${accountId}`;
  }
  document.title = `${accountName} | ${labels.sections_label}`;

  function openMenu(){
    menu.classList.add('open');
    menuButton.setAttribute('aria-expanded', 'true');
    const handler = (ev) => {
      if(!menu.contains(ev.target) && ev.target !== menuButton){
        closeMenu();
      }
    };
    document.addEventListener('click', handler, { once:true });
  }

  function closeMenu(){
    menu.classList.remove('open');
    menuButton.setAttribute('aria-expanded', 'false');
  }

  menuButton.addEventListener('click', (e) => {
    e.stopPropagation();
    if(menu.classList.contains('open')) closeMenu(); else openMenu();
  });

  function openModal(){
    sectionMsg.textContent = '';
    sectionForm.reset();
    modal.classList.remove('hidden');
    setTimeout(() => sectionSlugInput.focus(), 0);
  }

  function closeModal(){
    modal.classList.add('hidden');
    sectionMsg.textContent = '';
  }

  if(emptyCreateBtn){
    emptyCreateBtn.addEventListener('click', (e) => {
      e.preventDefault();
      openModal();
    });
  }

  sectionCancel.addEventListener('click', (e) => {
    e.preventDefault();
    closeModal();
  });

  document.addEventListener('keydown', (e) => {
    if(e.key === 'Escape'){
      closeMenu();
      closeModal();
    }
  });

  async function loadSections(){
    try{
      const sections = await api(`/api/accounts/${accountId}/sections`);
      if(!sections.length){
        sectionListEl.innerHTML = '';
        emptyStateEl.classList.remove('hidden');
        return;
      }
      emptyStateEl.classList.add('hidden');
      sectionListEl.innerHTML = sections.map(s => `
        <div class="card" style="margin-bottom:8px;">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
            <div>
              <strong>${s.label}</strong>
              <div class="small"><code>${s.slug}</code></div>
            </div>
            <div>
              <a class="btn" href="/section.html?account=${encodeURIComponent(accountId)}&slug=${encodeURIComponent(s.slug)}">Open</a>
            </div>
          </div>
        </div>
      `).join('');
    }catch(e){
      sectionListEl.innerHTML = `<p class="small">Failed to load sections: ${e.message}</p>`;
      emptyStateEl.classList.add('hidden');
    }
  }

  await loadSections();

  // Section create form (modal)
  sectionForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    sectionMsg.textContent = 'Saving…';
    const rawSlug = sectionSlugInput.value;
    const label = sectionLabelInput.value.trim();
    const slug = slugify(rawSlug);

    if(slug === 'default'){
      sectionMsg.textContent = '"default" is reserved. Choose another slug.';
      return;
    }

    try {
      await api(`/api/accounts/${accountId}/sections`, {
        method:'POST',
        body: JSON.stringify({ slug, label: label || slug, schema: {} })
      });
      sectionMsg.textContent = 'Section saved.';
      closeModal();
      await loadSections();
    } catch(err){
      sectionMsg.textContent = err.message || 'Failed to save section';
    }
  });

  // 3-dot menu actions
  menu.addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-action]');
    if(!btn) return;
    const action = btn.dataset.action;
    closeMenu();

    if(action === 'add-section'){
      openModal();
    } else if(action === 'edit'){
      const next = prompt('Account name', accountName);
      if(!next) return;
      const trimmed = next.trim();
      if(!trimmed || trimmed === accountName) return;
      try {
        const updated = await api(`/api/accounts/${accountId}`, {
          method:'PUT',
          body: JSON.stringify({ name: trimmed })
        });
        accountName = updated.name;
        acctNameEl.textContent = updated.name;
      } catch(err){
        alert(err.message || 'Failed to update account');
      }
    } else if(action === 'delete'){
      if(!confirm('Delete this account and all its data? This cannot be undone.')){
        return;
      }
      try {
        await api(`/api/accounts/${accountId}`, { method:'DELETE' });
        window.location.replace('/accounts.html');
      } catch(err){
        alert(err.message || 'Failed to delete account');
      }
    }
  });
})();
JS

# Section page logic (schema-driven table + modal + menu)
cat > "$WEB_JS_DIR/section.js" <<'JS'
import { loadMeOrRedirect, renderShell, api, getLabels } from './common.js';

function qs(name){
  const m = new URLSearchParams(location.search).get(name);
  return m && decodeURIComponent(m);
}

function escapeHtml(str){
  return String(str ?? '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

function formatCellValue(val){
  if(val === null || val === undefined) return '';
  if(typeof val === 'object'){
    try{
      const s = JSON.stringify(val);
      return s.length > 40 ? escapeHtml(s.slice(0, 37) + '…') : escapeHtml(s);
    }catch{
      return escapeHtml(String(val));
    }
  }
  return escapeHtml(String(val));
}

function parseLooseValue(str){
  const trimmed = str.trim();
  if(!trimmed) return '';
  // Try JSON parse for structured/typed values
  try {
    return JSON.parse(trimmed);
  } catch {
    return str;
  }
}

(async () => {
  const me = await loadMeOrRedirect(); if(!me) return;
  renderShell(me);
  const labels = getLabels(me);

  const accountId = qs('account');
  const slug = qs('slug');
  if(!accountId || !slug){
    document.body.innerHTML = '<main class="container"><p>Missing account or section.</p></main>';
    return;
  }

  const backLink = document.getElementById('backLink');
  const titleEl = document.getElementById('sectionTitle');
  const metaEl = document.getElementById('sectionMeta');
  const itemsEmptyState = document.getElementById('itemsEmptyState');
  const itemsTableContainer = document.getElementById('itemsTableContainer');
  const addItemButton = document.getElementById('addItemButton');
  const emptyAddItemButton = document.getElementById('emptyAddItemButton');
  const itemsHeading = document.getElementById('itemsHeading');
  const itemsEmptyCopy = document.getElementById('itemsEmptyCopy');
  const itemModalTitle = document.getElementById('itemModalTitle');

  const menuButton = document.getElementById('sectionMenuButton');
  const menu = document.getElementById('sectionMenu');
  const editSectionMenuLabel = document.getElementById('editSectionMenuLabel');
  const addItemMenuLabel = document.getElementById('addItemMenuLabel');
  const deleteSectionMenuLabel = document.getElementById('deleteSectionMenuLabel');

  const itemModal = document.getElementById('itemModal');
  const itemForm = document.getElementById('itemForm');
  const itemNameInput = document.getElementById('itemName');
  const itemMsg = document.getElementById('itemMsg');
  const itemCancel = document.getElementById('itemCancel');
  const schemaFieldsContainer = document.getElementById('schemaFieldsContainer');
  const kvEditorContainer = document.getElementById('kvEditorContainer');
  const kvRowsTbody = document.getElementById('kvRows');
  const addKVRowBtn = document.getElementById('addKVRowBtn');

  if(itemsHeading){ itemsHeading.textContent = labels.items_label; }
  if(addItemButton){ addItemButton.textContent = `Add ${labels.items_label}`; }
  if(emptyAddItemButton){ emptyAddItemButton.textContent = `Add your first ${labels.items_label.toLowerCase()}`; }
  if(itemsEmptyCopy){ itemsEmptyCopy.textContent = `No ${labels.items_label.toLowerCase()} in this ${labels.sections_label.toLowerCase()} yet.`; }
  if(editSectionMenuLabel){ editSectionMenuLabel.textContent = `Edit ${labels.sections_label}`; }
  if(addItemMenuLabel){ addItemMenuLabel.textContent = `Add ${labels.items_label}`; }
  if(deleteSectionMenuLabel){ deleteSectionMenuLabel.textContent = `Delete ${labels.sections_label}`; }
  if(itemModalTitle){ itemModalTitle.textContent = `Add ${labels.items_label}`; }

  if(backLink){
    backLink.href = `/account.html?id=${encodeURIComponent(accountId)}`;
  }

  let accountName = `Account ${accountId}`;
  try {
    const myAccounts = await api('/api/me/accounts');
    const match = myAccounts.find(a => a.id === accountId);
    if(match) accountName = match.name;
  } catch {
    // ignore
  }

  let currentSection = null;
  let schemaFields = []; // section.schema.fields || []

  async function loadSectionMeta(){
    try {
      const section = await api(`/api/accounts/${accountId}/sections/${encodeURIComponent(slug)}`);
      currentSection = section;
      titleEl.textContent = section.label;
      metaEl.textContent = `${accountName} · slug: ${section.slug}`;
      const s = section.schema || {};
      schemaFields = Array.isArray(s.fields) ? s.fields : [];
      document.title = `${section.label} | ${labels.sections_label}`;
    } catch {
      titleEl.textContent = `Section ${slug}`;
      metaEl.textContent = accountName;
      currentSection = { slug, label: slug, schema: {} };
      schemaFields = [];
      document.title = `${labels.sections_label} ${slug}`;
    }
  }

  function openMenu(){
    menu.classList.add('open');
    menuButton.setAttribute('aria-expanded', 'true');
    const handler = (ev) => {
      if(!menu.contains(ev.target) && ev.target !== menuButton){
        closeMenu();
      }
    };
    document.addEventListener('click', handler, { once:true });
  }

  function closeMenu(){
    menu.classList.remove('open');
    menuButton.setAttribute('aria-expanded', 'false');
  }

  menuButton.addEventListener('click', (e) => {
    e.stopPropagation();
    if(menu.classList.contains('open')) closeMenu(); else openMenu();
  });

  document.addEventListener('keydown', (e) => {
    if(e.key === 'Escape'){
      closeMenu();
      closeItemModal();
    }
  });

  function openItemModal(){
    itemMsg.textContent = '';
    itemForm.reset();
    // Setup UI depending on schema
    if(schemaFields && schemaFields.length){
      schemaFieldsContainer.innerHTML = schemaFields.map(f => {
        const type = (f.type || 'text').toLowerCase();
        const required = f.required ? 'required' : '';
        const keyAttr = `data-key="${escapeHtml(f.key)}" data-type="${escapeHtml(type)}"`;
        if(type === 'textarea'){
          return `<p><label>${escapeHtml(f.label || f.key)}<textarea ${keyAttr} ${required}></textarea></label></p>`;
        } else if(type === 'select' && Array.isArray(f.options)) {
          const opts = f.options.map(o => `<option value="${escapeHtml(String(o))}">${escapeHtml(String(o))}</option>`).join('');
          return `<p><label>${escapeHtml(f.label || f.key)}<select ${keyAttr} ${required}>${opts}</select></label></p>`;
        } else if(type === 'checkbox') {
          return `<p><label><input type="checkbox" ${keyAttr}> ${escapeHtml(f.label || f.key)}</label></p>`;
        } else {
          return `<p><label>${escapeHtml(f.label || f.key)}<input type="text" ${keyAttr} ${required}></label></p>`;
        }
      }).join('');
      schemaFieldsContainer.classList.remove('hidden');
      kvEditorContainer.classList.add('hidden');
    } else {
      // Fallback key/value editor
      schemaFieldsContainer.classList.add('hidden');
      kvEditorContainer.classList.remove('hidden');
      kvRowsTbody.innerHTML = '';
      addKVRow();
    }
    itemModal.classList.remove('hidden');
    setTimeout(() => itemNameInput.focus(), 0);
  }

  function closeItemModal(){
    itemModal.classList.add('hidden');
    itemMsg.textContent = '';
  }

  function addKVRow(key='', value=''){
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><input type="text" class="kv-key" value="${escapeHtml(key)}"></td>
      <td><input type="text" class="kv-value" value="${escapeHtml(value)}"></td>
      <td style="width:1%;white-space:nowrap;">
        <button type="button" class="kv-remove-btn" title="Remove row">×</button>
      </td>
    `;
    const btn = tr.querySelector('.kv-remove-btn');
    btn.addEventListener('click', () => {
      tr.remove();
    });
    kvRowsTbody.appendChild(tr);
  }

  if(addKVRowBtn){
    addKVRowBtn.addEventListener('click', (e) => {
      e.preventDefault();
      addKVRow();
    });
  }

  if(addItemButton){
    addItemButton.addEventListener('click', (e) => {
      e.preventDefault();
      openItemModal();
    });
  }
  if(emptyAddItemButton){
    emptyAddItemButton.addEventListener('click', (e) => {
      e.preventDefault();
      openItemModal();
    });
  }

  if(itemCancel){
    itemCancel.addEventListener('click', (e) => {
      e.preventDefault();
      closeItemModal();
    });
  }

  async function loadItems(){
    try{
      const page = await api(`/api/accounts/${accountId}/sections/${encodeURIComponent(slug)}/items?limit=200`);
      const items = page.items || [];
      if(!items.length){
        itemsEmptyState.classList.remove('hidden');
        itemsTableContainer.innerHTML = '';
        return;
      }
      itemsEmptyState.classList.add('hidden');
      const html = renderItemsTable(items);
      itemsTableContainer.innerHTML = html;
    }catch(e){
      itemsTableContainer.innerHTML = `<p class="small">Failed to load items: ${e.message}</p>`;
      itemsEmptyState.classList.add('hidden');
    }
  }

  function renderItemsTable(items){
    const hasSchema = schemaFields && schemaFields.length;
    if(hasSchema){
      return renderSchemaTable(items, schemaFields);
    }
    return renderAutoTable(items);
  }

  function renderSchemaTable(items, fields){
    const visibleFields = fields.filter(f => f.showInTable !== false);
    const headers = ['Name', ...visibleFields.map(f => f.label || f.key), ''];
    const headerHtml = '<tr>' + headers.map(h => `<th>${escapeHtml(h)}</th>`).join('') + '</tr>';
    const rowsHtml = items.map(it => {
      const cells = [];
      cells.push(`<td>${escapeHtml(it.name)}</td>`);
      for(const f of visibleFields){
        const key = f.key;
        const val = it.data && typeof it.data === 'object' ? it.data[key] : undefined;
        cells.push(`<td>${formatCellValue(val)}</td>`);
      }
      const viewHref = `/item.html?account=${encodeURIComponent(accountId)}&section=${encodeURIComponent(slug)}&item=${encodeURIComponent(it.id)}`;
      cells.push(`<td style="width:1%;white-space:nowrap;"><a class="btn small" href="${viewHref}">View</a></td>`);
      return `<tr>${cells.join('')}</tr>`;
    }).join('');

    return `<div class="table-wrapper"><table><thead>${headerHtml}</thead><tbody>${rowsHtml}</tbody></table></div>`;
  }

  function renderAutoTable(items){
    const keySet = new Set();
    for(const it of items){
      if(it.data && typeof it.data === 'object'){
        Object.keys(it.data).forEach(k => keySet.add(k));
      }
    }
    let keys = Array.from(keySet);
    // Optional: move common keys to front
    const priority = ['title','name','label'];
    keys.sort((a,b) => {
      const ia = priority.indexOf(a.toLowerCase());
      const ib = priority.indexOf(b.toLowerCase());
      if(ia !== -1 && ib === -1) return -1;
      if(ib !== -1 && ia === -1) return 1;
      return a.localeCompare(b);
    });
    // Limit columns to avoid over-wide tables
    const MAX_COLS = 8;
    if(keys.length > MAX_COLS) keys = keys.slice(0, MAX_COLS);

    const headers = ['Name', ...keys, ''];
    const headerHtml = '<tr>' + headers.map(h => `<th>${escapeHtml(h)}</th>`).join('') + '</tr>';

    const rowsHtml = items.map(it => {
      const cells = [];
      cells.push(`<td>${escapeHtml(it.name)}</td>`);
      for(const k of keys){
        const val = it.data && typeof it.data === 'object' ? it.data[k] : undefined;
        cells.push(`<td>${formatCellValue(val)}</td>`);
      }
      const viewHref = `/item.html?account=${encodeURIComponent(accountId)}&section=${encodeURIComponent(slug)}&item=${encodeURIComponent(it.id)}`;
      cells.push(`<td style="width:1%;white-space:nowrap;"><a class="btn small" href="${viewHref}">View</a></td>`);
      return `<tr>${cells.join('')}</tr>`;
    }).join('');

    return `<div class="table-wrapper"><table><thead>${headerHtml}</thead><tbody>${rowsHtml}</tbody></table></div>`;
  }

  // Item form submit
  itemForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    itemMsg.textContent = 'Saving…';
    const name = itemNameInput.value.trim();
    if(!name){
      itemMsg.textContent = 'Name is required.';
      return;
    }

    let data = {};
    if(schemaFields && schemaFields.length){
      const inputs = schemaFieldsContainer.querySelectorAll('[data-key]');
      inputs.forEach(el => {
        const key = el.getAttribute('data-key');
        const type = (el.getAttribute('data-type') || 'text').toLowerCase();
        if(type === 'checkbox'){
          data[key] = el.checked;
        } else {
          data[key] = parseLooseValue(el.value);
        }
      });
    } else {
      const rows = kvRowsTbody.querySelectorAll('tr');
      rows.forEach(row => {
        const kInput = row.querySelector('.kv-key');
        const vInput = row.querySelector('.kv-value');
        if(!kInput) return;
        const key = kInput.value.trim();
        if(!key) return;
        const raw = vInput ? vInput.value : '';
        data[key] = parseLooseValue(raw);
      });
    }

    try {
      await api(`/api/accounts/${accountId}/sections/${encodeURIComponent(slug)}/items`, {
        method:'POST',
        body: JSON.stringify({ name, data })
      });
      itemMsg.textContent = 'Item added.';
      closeItemModal();
      await loadItems();
    } catch(err){
      itemMsg.textContent = err.message || 'Failed to add item';
    }
  });

  // 3-dot menu actions
  menu.addEventListener('click', async (e) => {
    const btn = e.target.closest('button[data-action]');
    if(!btn) return;
    const action = btn.dataset.action;
    closeMenu();

    if(action === 'add-item'){
      openItemModal();
    } else if(action === 'edit'){
      const currentLabel = currentSection?.label || slug;
      const next = prompt('Section name', currentLabel);
      if(!next) return;
      const trimmed = next.trim();
      if(!trimmed || trimmed === currentLabel) return;
      try {
        const updated = await api(`/api/accounts/${accountId}/sections/${encodeURIComponent(slug)}`, {
          method:'PUT',
          body: JSON.stringify({ label: trimmed, schema: currentSection?.schema || {} })
        });
        currentSection = updated;
        titleEl.textContent = updated.label;
      } catch(err){
        alert(err.message || 'Failed to update section');
      }
    } else if(action === 'delete'){
      if(!confirm('Delete this section and all its items? This cannot be undone.')){
        return;
      }
      try {
        await api(`/api/accounts/${accountId}/sections/${encodeURIComponent(slug)}`, { method:'DELETE' });
        window.location.replace(`/account.html?id=${encodeURIComponent(accountId)}`);
      } catch(err){
        alert(err.message || 'Failed to delete section');
      }
    }
  });

  await loadSectionMeta();
  await loadItems();
})();
JS

# Item detail page logic (vertical layout)
cat > "$WEB_JS_DIR/item.js" <<'JS'
import { loadMeOrRedirect, renderShell, api, getLabels } from './common.js';

function qs(name){
  const m = new URLSearchParams(location.search).get(name);
  return m && decodeURIComponent(m);
}

function escapeHtml(str){
  return String(str ?? '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;');
}

function formatValue(val){
  if(val === null || val === undefined) return '';
  if(typeof val === 'object'){
    try{
      return escapeHtml(JSON.stringify(val, null, 2));
    }catch{
      return escapeHtml(String(val));
    }
  }
  return escapeHtml(String(val));
}

(async () => {
  const me = await loadMeOrRedirect(); if(!me) return;
  renderShell(me);
  const labels = getLabels(me);
  document.title = labels.items_label;

  const accountId = qs('account');
  const sectionSlug = qs('section');
  const itemId = qs('item');

  const backToSection = document.getElementById('backToSection');
  const itemNameEl = document.getElementById('itemName');
  const itemMetaEl = document.getElementById('itemMeta');
  const itemPropsBody = document.getElementById('itemProperties');
  const itemRaw = document.getElementById('itemRaw');

  if(!accountId || !itemId){
    document.body.innerHTML = '<main class="container"><p>Missing account or item id.</p></main>';
    return;
  }

  if(backToSection){
    if(sectionSlug){
      backToSection.href = `/section.html?account=${encodeURIComponent(accountId)}&slug=${encodeURIComponent(sectionSlug)}`;
    } else {
      backToSection.href = `/account.html?id=${encodeURIComponent(accountId)}`;
    }
  }

  let accountName = `Account ${accountId}`;
  try {
    const myAccounts = await api('/api/me/accounts');
    const match = myAccounts.find(a => a.id === accountId);
    if(match) accountName = match.name;
  } catch {
    // ignore
  }

  let section = null;
  let schemaFields = [];
  if(sectionSlug){
    try {
      section = await api(`/api/accounts/${accountId}/sections/${encodeURIComponent(sectionSlug)}`);
      const s = section.schema || {};
      schemaFields = Array.isArray(s.fields) ? s.fields : [];
    } catch {
      section = null;
      schemaFields = [];
    }
  }

  try {
    const item = await api(`/api/accounts/${accountId}/items/${encodeURIComponent(itemId)}`);
    itemNameEl.textContent = item.name;
    const sectionLabel = section ? section.label : (sectionSlug || 'No section');
    itemMetaEl.textContent = `${accountName} · ${labels.sections_label}: ${sectionLabel} · id: ${itemId}`;
    document.title = `${item.name} | ${labels.items_label}`;

    const data = item.data || {};
    const rows = [];

    // If schema present, respect its order/labels
    if(schemaFields.length){
      const usedKeys = new Set();
      for(const f of schemaFields){
        const key = f.key;
        usedKeys.add(key);
        const label = f.label || key;
        const val = data ? data[key] : undefined;
        rows.push({ label, value: val });
      }
      // Include any extra keys not in schema at the bottom
      if(data && typeof data === 'object'){
        Object.keys(data).forEach(k => {
          if(usedKeys.has(k)) return;
          rows.push({ label: k, value: data[k] });
        });
      }
    } else {
      // No schema: list keys alphabetically
      if(data && typeof data === 'object'){
        Object.keys(data).sort().forEach(k => {
          rows.push({ label: k, value: data[k] });
        });
      }
    }

    if(!rows.length){
      itemPropsBody.innerHTML = `<tr><td class="small" colspan="2">No properties for this ${labels.items_label.toLowerCase()}.</td></tr>`;
    } else {
      itemPropsBody.innerHTML = rows.map(r => `
        <tr>
          <th>${escapeHtml(r.label)}</th>
          <td><pre style="margin:0;white-space:pre-wrap;">${formatValue(r.value)}</pre></td>
        </tr>
      `).join('');
    }

    try {
      itemRaw.textContent = JSON.stringify(item.data || {}, null, 2);
    } catch {
      itemRaw.textContent = String(item.data || '');
    }
  } catch(e){
    itemNameEl.textContent = 'Item not found';
    itemMetaEl.textContent = e.message || 'Failed to load item.';
    itemPropsBody.innerHTML = '';
    itemRaw.textContent = '';
  }
})();
JS

# --- helper scripts ---
cat > "$SCRIPTS_DIR/create_tenant.sh" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
ACC_NAME=${1:-}
if [[ -z "$ACC_NAME" ]]; then echo "Usage: $0 <ACCOUNT_NAME>"; exit 1; fi
source "$(dirname "$0")/../.env"
PSQL="docker compose exec -T db psql -U $POSTGRES_USER -d $POSTGRES_DB -v ON_ERROR_STOP=1"

ACC_ID=$($PSQL -t -A -c "INSERT INTO accounts(name) VALUES ($$${ACC_NAME}$$) RETURNING id;")
ACC_ID=$(echo "$ACC_ID" | tr -d '[:space:]')

$PSQL -c "DO $$
DECLARE sch text := 'tenant_' || replace('$ACC_ID','-','');
BEGIN
  EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', sch);
  -- Ensure items table exists with section support.
  EXECUTE format('CREATE TABLE IF NOT EXISTS %I.items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    section_slug TEXT NOT NULL DEFAULT ''default'',
    name TEXT NOT NULL,
    data JSONB NOT NULL DEFAULT ''{}'',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )', sch);
  EXECUTE format('ALTER TABLE %I.items ADD COLUMN IF NOT EXISTS section_slug TEXT', sch);
  EXECUTE format('UPDATE %I.items SET section_slug = ''default'' WHERE section_slug IS NULL', sch);
  EXECUTE format('ALTER TABLE %I.items ALTER COLUMN section_slug SET DEFAULT ''default''', sch);
  EXECUTE format('ALTER TABLE %I.items ALTER COLUMN section_slug SET NOT NULL', sch);
  EXECUTE format('ALTER TABLE %I.items ENABLE ROW LEVEL SECURITY', sch);
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname=sch AND tablename='items' AND policyname='items_tenant_policy') THEN
    EXECUTE format('CREATE POLICY items_tenant_policy ON %I.items
      USING ( current_setting(''app.current_account'')::uuid = ''$ACC_ID'' )
      WITH CHECK ( current_setting(''app.current_account'')::uuid = ''$ACC_ID'' )', sch);
  END IF;
END $$;"
printf "Created account '%s' (%s) with schema tenant_%s\n" "$ACC_NAME" "$ACC_ID" "${ACC_ID//-/}"
BASH
$SUDO chmod +x "$SCRIPTS_DIR/create_tenant.sh"

cat > "$SCRIPTS_DIR/rotate_secret.sh" <<'BASH'
#!/usr/bin/env bash
set -euo pipefail
FILE="$(dirname "$0")/../.env"
sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" "$FILE"
docker compose up -d --force-recreate api caddy
echo "Rotated JWT secret; existing tokens are now invalid."
BASH
$SUDO chmod +x "$SCRIPTS_DIR/rotate_secret.sh"

echo "[5/7] Installing systemd unit…"
cat > /tmp/stack.service <<'UNIT'
[Unit]
Description=Multi-tenant Stack (Docker Compose)
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
WorkingDirectory=/opt/stack
RemainAfterExit=true
ExecStart=/usr/bin/docker compose up -d --remove-orphans
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
UNIT
$SUDO mv /tmp/stack.service /etc/systemd/system/stack.service
$SUDO systemctl daemon-reload
$SUDO systemctl enable stack || true

echo "[6/7] Configuring UFW…"
$SUDO ufw default deny incoming || true
$SUDO ufw default allow outgoing || true
$SUDO ufw allow 22/tcp || true
$SUDO ufw allow 80/tcp || true
$SUDO ufw allow 443/tcp || true
echo "y" | $SUDO ufw enable || true

echo "[7/7] Building images (api + web)…"
docker compose build api web

echo "[7/7] Starting containers…"
# Prefer systemd, fall back to plain docker compose if needed
$SUDO systemctl start stack || docker compose up -d --remove-orphans

cat <<DONE

✅ All set.

Default login:
  Email: ${ADMIN_EMAIL}
  Password: (from .env) — currently '${ADMIN_PASSWORD}'

Pages:
  /                             → login
  /accounts.html                → list your accounts
  /account.html?id=<ACCOUNT_ID> → account details (sections list + 3-dot menu + modal "Create section")
  /section.html?account=<ACCOUNT_ID>&slug=<SLUG>
                                → schema-driven items table + 3-dot menu + item modal
  /item.html?account=<ACCOUNT_ID>&section=<SLUG>&item=<ITEM_ID>
                                → item detail (vertical layout)
  /customisation.html           → per-user label settings (admin)
  /settings.html                → settings hub (admin)
  /admin.html                   → list users + roles, customisation visibility for super admins, link to "Add user"
  /admin-add.html               → create user with role, name, accounts, and inherited customisations

API (extended):
  POST /api/login
  GET  /api/me
  GET  /api/me/preferences
  PUT  /api/me/preferences
  GET  /api/me/accounts

  # Accounts
  POST   /api/accounts
  PUT    /api/accounts/{id}
  DELETE /api/accounts/{id}

  # Default items (section_slug = "default")
  GET    /api/accounts/{id}/items
  POST   /api/accounts/{id}/items
  GET    /api/accounts/{id}/items/{item_id}
  PUT    /api/accounts/{id}/items/{item_id}
  DELETE /api/accounts/{id}/items/{item_id}

  # Sections
  GET    /api/accounts/{id}/sections
  POST   /api/accounts/{id}/sections
  GET    /api/accounts/{id}/sections/{slug}
  PUT    /api/accounts/{id}/sections/{slug}
  DELETE /api/accounts/{id}/sections/{slug}
  GET    /api/accounts/{id}/sections/{slug}/items
  POST   /api/accounts/{id}/sections/{slug}/items

  # Admin
  GET  /api/admin/all-accounts (admin)
  GET  /api/admin/users        (admin)
  POST /api/admin/users        (admin) {email,password,accounts:[ids]}

Schema for section-driven UIs (stored in sections.schema):
  {
    "fields": [
      {
        "key": "title",
        "label": "Title",
        "type": "text",
        "required": true,
        "showInTable": true
      },
      {
        "key": "status",
        "label": "Status",
        "type": "select",
        "options": ["Open","In progress","Closed"],
        "showInTable": true
      }
    ]
  }

If schema.fields is empty or missing:
  - Section items table falls back to an auto-generated table using data keys.
  - Item modal falls back to a key/value editor.

DONE
