"""TendoConnect Technologies - Customer & Hotspot Management API (single-file backend)."""
import logging, os, re, secrets, threading, time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

import bcrypt, jwt, psycopg, psycopg_pool, requests
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBearer
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field, field_validator

load_dotenv()
log = logging.getLogger("tendoconnect")
DATABASE_URL, SECRET_KEY = os.getenv("DATABASE_URL"), os.getenv("SECRET_KEY")
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "").rstrip("/")  # public https address of this app
FRONTEND_URL = (os.getenv("FRONTEND_URL") or PUBLIC_BASE_URL).rstrip("/")  # where customers see their receipt
PESAPAL_KEY, PESAPAL_SECRET = os.getenv("PESAPAL_CONSUMER_KEY"), os.getenv("PESAPAL_CONSUMER_SECRET")
PESAPAL_ENV = os.getenv("PESAPAL_ENVIRONMENT", "live").lower()  # "sandbox" or "live" — defaults to live, same as ScienceTech
PESAPAL_BASE = "https://pay.pesapal.com/v3" if PESAPAL_ENV == "live" else "https://cybqa.pesapal.com/pesapalv3"
PESAPAL_CALLBACK_URL = os.getenv("PESAPAL_CALLBACK_URL") or f"{PUBLIC_BASE_URL}/api/pesapal/callback"
PESAPAL_IPN_URL = os.getenv("PESAPAL_IPN_URL") or f"{PUBLIC_BASE_URL}/api/pesapal/ipn"
_missing = [k for k, v in {"DATABASE_URL": DATABASE_URL, "SECRET_KEY": SECRET_KEY, "PUBLIC_BASE_URL": PUBLIC_BASE_URL,
                           "PESAPAL_CONSUMER_KEY": PESAPAL_KEY, "PESAPAL_CONSUMER_SECRET": PESAPAL_SECRET}.items() if not v]
if _missing:
    raise RuntimeError("Missing required environment variables: " + ", ".join(_missing) + " (see .env.example).")
if len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY must be at least 32 characters.")
if PESAPAL_ENV == "live" and not PUBLIC_BASE_URL.startswith("https://"):
    raise RuntimeError("PUBLIC_BASE_URL must be an https:// address for live payments.")

# ---------------------------------------------------------------- database
pool = ConnectionPool(DATABASE_URL, min_size=1, max_size=5, open=False,
                      check=ConnectionPool.check_connection, kwargs={"row_factory": dict_row})

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers(id SERIAL PRIMARY KEY, full_name TEXT NOT NULL, phone TEXT NOT NULL UNIQUE,
  email TEXT, status TEXT NOT NULL DEFAULT 'Active' CHECK(status IN('Active','Inactive','Suspended')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS packages(id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT DEFAULT '',
  price INT NOT NULL CHECK(price>=0), duration INT NOT NULL CHECK(duration>0),
  duration_unit TEXT NOT NULL CHECK(duration_unit IN('Minutes','Hours','Days')),
  active BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS hotspots(id SERIAL PRIMARY KEY, name TEXT NOT NULL UNIQUE, location TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'Offline' CHECK(status IN('Online','Offline','Maintenance')),
  device_id TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS orders(id SERIAL PRIMARY KEY, ref TEXT NOT NULL UNIQUE,
  customer_id INT NOT NULL REFERENCES customers(id), package_id INT NOT NULL REFERENCES packages(id),
  hotspot_id INT REFERENCES hotspots(id), amount INT NOT NULL, currency TEXT NOT NULL DEFAULT 'UGX',
  status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN('Pending','Paid','Failed','Cancelled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS payments(id SERIAL PRIMARY KEY, order_id INT NOT NULL UNIQUE REFERENCES orders(id),
  customer_id INT NOT NULL REFERENCES customers(id), package_id INT NOT NULL REFERENCES packages(id),
  amount INT NOT NULL, currency TEXT NOT NULL DEFAULT 'UGX',
  method TEXT NOT NULL DEFAULT 'Other' CHECK(method IN('Mobile Money','Card','Cash','Other')),
  provider TEXT NOT NULL CHECK(provider IN('Pesapal','Manual','Mock','Other')), provider_txn_id TEXT,
  status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN('Pending','Completed','Failed','Cancelled','Refunded')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), paid_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS sessions(id SERIAL PRIMARY KEY, order_id INT NOT NULL UNIQUE REFERENCES orders(id),
  customer_id INT NOT NULL REFERENCES customers(id), package_id INT NOT NULL REFERENCES packages(id),
  hotspot_id INT REFERENCES hotspots(id), started_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
  status TEXT NOT NULL DEFAULT 'Active' CHECK(status IN('Active','Expired','Suspended','Terminated')),
  mikrotik_username TEXT, voucher_code TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS voucher_code TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS ix_sessions_voucher ON sessions(voucher_code) WHERE voucher_code IS NOT NULL;
CREATE TABLE IF NOT EXISTS admins(id SERIAL PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now());
ALTER TABLE admins ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'Admin' CHECK(role IN('Admin','SuperAdmin'));
ALTER TABLE admins ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true;
CREATE TABLE IF NOT EXISTS withdrawals(id SERIAL PRIMARY KEY, admin_id INT NOT NULL REFERENCES admins(id),
  admin_username TEXT NOT NULL, amount INT NOT NULL CHECK(amount>0),
  method TEXT NOT NULL DEFAULT 'Mobile Money' CHECK(method IN('Mobile Money','Bank Transfer','Cash')),
  destination TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN('Pending','Paid','Rejected')),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(), processed_at TIMESTAMPTZ, processed_by TEXT, reject_reason TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS ix_payments_txn ON payments(provider_txn_id);
CREATE INDEX IF NOT EXISTS ix_orders_customer ON orders(customer_id);
CREATE INDEX IF NOT EXISTS ix_payments_customer ON payments(customer_id, status);
CREATE INDEX IF NOT EXISTS ix_sessions_customer ON sessions(customer_id, expires_at);
CREATE INDEX IF NOT EXISTS ix_withdrawals_status ON withdrawals(status);
CREATE INDEX IF NOT EXISTS ix_withdrawals_admin ON withdrawals(admin_id);
"""
SEED_PACKAGES = [("5 Hours", 500, 5, "Hours"), ("24 Hours", 1000, 24, "Hours"), ("1 Week", 5000, 7, "Days"),
                 ("2 Weeks", 10000, 14, "Days"), ("1 Month", 20000, 30, "Days")]


def db(sql, args=(), one=False, conn=None):
    def go(c):
        cur = c.execute(sql, args)
        if cur.description is None:
            return None
        return cur.fetchone() if one else cur.fetchall()
    if conn:
        return go(conn)
    with pool.connection() as c:
        return go(c)


def found(row, msg="Not found."):
    if not row:
        raise HTTPException(404, msg)
    return row


@asynccontextmanager
async def lifespan(_):
    pool.open()
    db(SCHEMA)
    if not db("SELECT 1 FROM packages LIMIT 1", one=True):  # starter packages, editable in the dashboard
        for n, p, d, u in SEED_PACKAGES:
            db("INSERT INTO packages(name,price,duration,duration_unit) VALUES(%s,%s,%s,%s)", (n, p, d, u))
    # Databases created before roles existed get their earliest admin promoted, so nobody is locked out.
    if db("SELECT 1 FROM admins LIMIT 1", one=True) and not db("SELECT 1 FROM admins WHERE role='SuperAdmin' LIMIT 1", one=True):
        db("UPDATE admins SET role='SuperAdmin' WHERE id=(SELECT id FROM admins ORDER BY id LIMIT 1)")
    expire_stale()
    try:
        pp_ipn_id()  # register the IPN URL with Pesapal early so problems show in the logs at startup
    except Exception as e:
        log.warning("Pesapal IPN registration failed at startup: %s", e)
    yield
    pool.close()


app = FastAPI(title="TendoConnect Technologies API", version="1.0.0", lifespan=lifespan,
              description="Customers, packages, orders, payments, hotspots and sessions. "
                          "Payments are collected through Pesapal. Router (MikroTik) provisioning is not connected yet.")
origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
if FRONTEND_URL not in origins:
    origins.append(FRONTEND_URL)
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["*"], allow_headers=["*"])


@app.middleware("http")
async def security_headers(request: Request, call_next):
    r = await call_next(request)
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin"})
    return r


@app.exception_handler(psycopg.errors.UniqueViolation)
async def _dup(_, __):
    return JSONResponse({"detail": "That value already exists (for example, a duplicate phone number or name)."}, 409)


@app.exception_handler(psycopg.errors.ForeignKeyViolation)
async def _fk(_, __):
    return JSONResponse({"detail": "This record is still in use by other records."}, 409)


for _exc in (psycopg.OperationalError, psycopg_pool.PoolTimeout):
    @app.exception_handler(_exc)
    async def _down(_, __):
        return JSONResponse({"detail": "The service is temporarily unavailable. Please try again shortly."}, 503)


@app.exception_handler(Exception)
async def _boom(_, exc):
    log.exception("Unhandled error: %s", exc)
    return JSONResponse({"detail": "Something went wrong on our side. Please try again."}, 500)


# ---------------------------------------------------------------- auth
bearer = HTTPBearer(auto_error=False)


def admin(cred=Depends(bearer)):
    try:
        return jwt.decode(cred.credentials, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        raise HTTPException(401, "Please sign in again.")


def super_admin(a=Depends(admin)):
    """Gate for actions only a super admin may take, such as disbursing a withdrawal or managing admin accounts."""
    if a.get("role") != "SuperAdmin":
        raise HTTPException(403, "Only super admins can do this.")
    return a


class Login(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=1, max_length=200)


class Setup(Login):
    password: str = Field(min_length=10, max_length=200)
    setup_key: str


class AdminIn(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: Optional[str] = Field(None, min_length=8, max_length=200)  # required on create; leave blank on edit to keep it
    role: Literal["Admin", "SuperAdmin"] = "Admin"
    active: bool = True

    @field_validator("password", mode="before")
    @classmethod
    def _blank_password(cls, v):
        return v or None


def token_for(a):
    exp = datetime.now(timezone.utc) + timedelta(hours=8)
    return jwt.encode({"sub": a["username"], "aid": a["id"], "role": a["role"], "exp": exp}, SECRET_KEY, algorithm="HS256")


@app.get("/api/auth/status", tags=["Auth"])
def auth_status():
    """Tells the login screen whether the first admin still has to be created."""
    return {"setup_required": db("SELECT 1 FROM admins LIMIT 1", one=True) is None}


@app.post("/api/auth/setup", status_code=201, tags=["Auth"])
def auth_setup(b: Setup):
    """Create the first admin, as a super admin. Only works while no admin exists and requires SECRET_KEY as setup_key."""
    if db("SELECT 1 FROM admins LIMIT 1", one=True):
        raise HTTPException(409, "An admin already exists.")
    if not secrets.compare_digest(b.setup_key, SECRET_KEY):
        raise HTTPException(403, "Invalid setup key.")
    h = bcrypt.hashpw(b.password.encode(), bcrypt.gensalt()).decode()
    a = db("INSERT INTO admins(username,password_hash,role) VALUES(%s,%s,'SuperAdmin') RETURNING *", (b.username.lower(), h), one=True)
    return {"token": token_for(a), "username": a["username"], "role": a["role"]}


@app.post("/api/auth/login", tags=["Auth"])
def auth_login(b: Login, request: Request):
    throttle(request, "login", 10, 900)
    a = db("SELECT * FROM admins WHERE username=%s", (b.username.lower(),), one=True)
    if not a or not bcrypt.checkpw(b.password.encode(), a["password_hash"].encode()):
        raise HTTPException(401, "Wrong username or password.")
    if not a["active"]:
        raise HTTPException(403, "This admin account has been disabled. Contact a super admin.")
    return {"token": token_for(a), "username": a["username"], "role": a["role"]}


# ---------------------------------------------------------------- admin accounts (super admin only)
def _active_superadmins(exclude_id=None, conn=None):
    """Counts active super admins, optionally excluding one — used to stop the last one being demoted/deleted/disabled."""
    if exclude_id:
        return db("SELECT count(*)::int AS n FROM admins WHERE role='SuperAdmin' AND active AND id<>%s", (exclude_id,), one=True, conn=conn)["n"]
    return db("SELECT count(*)::int AS n FROM admins WHERE role='SuperAdmin' AND active", one=True, conn=conn)["n"]


@app.get("/api/admins", tags=["Admins"])
def admins_list(_=Depends(super_admin)):
    return db("SELECT id,username,role,active,created_at FROM admins ORDER BY id")


@app.post("/api/admins", status_code=201, tags=["Admins"])
def admins_create(b: AdminIn, _=Depends(super_admin)):
    """A super admin creates another admin account — regular or, to add another super admin, role='SuperAdmin'."""
    if not b.password:
        raise HTTPException(422, "A password is required for a new admin.")
    h = bcrypt.hashpw(b.password.encode(), bcrypt.gensalt()).decode()
    return db("INSERT INTO admins(username,password_hash,role,active) VALUES(%s,%s,%s,%s) RETURNING id,username,role,active,created_at",
              (b.username.lower(), h, b.role, b.active), one=True)


@app.put("/api/admins/{aid}", tags=["Admins"])
def admins_update(aid: int, b: AdminIn, _=Depends(super_admin)):
    with pool.connection() as c:
        cur = found(db("SELECT * FROM admins WHERE id=%s FOR UPDATE", (aid,), one=True, conn=c), "Admin not found.")
        stays_active_super = b.role == "SuperAdmin" and b.active
        if cur["role"] == "SuperAdmin" and cur["active"] and not stays_active_super and _active_superadmins(exclude_id=aid, conn=c) < 1:
            raise HTTPException(400, "At least one active super admin is required.")
        if b.password:
            h = bcrypt.hashpw(b.password.encode(), bcrypt.gensalt()).decode()
            row = db("UPDATE admins SET username=%s,password_hash=%s,role=%s,active=%s WHERE id=%s RETURNING id,username,role,active,created_at",
                     (b.username.lower(), h, b.role, b.active, aid), one=True, conn=c)
        else:
            row = db("UPDATE admins SET username=%s,role=%s,active=%s WHERE id=%s RETURNING id,username,role,active,created_at",
                     (b.username.lower(), b.role, b.active, aid), one=True, conn=c)
    return row


@app.delete("/api/admins/{aid}", tags=["Admins"])
def admins_delete(aid: int, a=Depends(super_admin)):
    if aid == a["aid"]:
        raise HTTPException(400, "You cannot delete your own account.")
    with pool.connection() as c:
        cur = found(db("SELECT * FROM admins WHERE id=%s FOR UPDATE", (aid,), one=True, conn=c), "Admin not found.")
        if cur["role"] == "SuperAdmin" and cur["active"] and _active_superadmins(exclude_id=aid, conn=c) < 1:
            raise HTTPException(400, "At least one active super admin is required.")
        db("DELETE FROM admins WHERE id=%s", (aid,), conn=c)
    return {"ok": True}


# ---------------------------------------------------------------- models
def norm_phone(v: str) -> str:
    d = re.sub(r"\D", "", v or "")
    if len(d) == 10 and d.startswith("0"):
        d = "256" + d[1:]
    elif len(d) == 9:
        d = "256" + d
    if not re.fullmatch(r"\d{11,15}", d):
        raise ValueError("Enter a valid phone number, e.g. 0772 123 456")
    return "+" + d


class CustomerIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    phone: str
    email: Optional[str] = Field(None, max_length=160)
    status: Literal["Active", "Inactive", "Suspended"] = "Active"

    @field_validator("phone")
    @classmethod
    def _phone(cls, v):
        return norm_phone(v)

    @field_validator("email")
    @classmethod
    def _email(cls, v):
        if not v:
            return None
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
            raise ValueError("Enter a valid email address")
        return v


class PackageIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    description: str = Field("", max_length=300)
    price: int = Field(ge=0, le=10_000_000)
    duration: int = Field(gt=0, le=100_000)
    duration_unit: Literal["Minutes", "Hours", "Days"]
    active: bool = True


class HotspotIn(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    location: str = Field("", max_length=200)
    status: Literal["Online", "Offline", "Maintenance"] = "Offline"
    device_id: Optional[str] = Field(None, max_length=100)


class OrderIn(BaseModel):
    phone: str
    package_id: int
    hotspot_id: Optional[int] = None

    @field_validator("phone")
    @classmethod
    def _phone(cls, v):
        return norm_phone(v)


class PortalIn(BaseModel):
    phone: str
    receipt: str = Field(min_length=4, max_length=40)

    @field_validator("phone")
    @classmethod
    def _phone(cls, v):
        return norm_phone(v)


class WithdrawalIn(BaseModel):
    amount: int = Field(gt=0, le=100_000_000)
    method: Literal["Mobile Money", "Bank Transfer", "Cash"] = "Mobile Money"
    destination: str = Field("", max_length=200)
    notes: str = Field("", max_length=300)


class RejectIn(BaseModel):
    reason: str = Field("", max_length=300)


# ---------------------------------------------------------------- helpers
_hits: dict = {}


def throttle(request: Request, key: str, limit: int, window: int):
    """Small in-memory per-IP rate limit (per process). Run uvicorn with --proxy-headers behind a proxy."""
    now, k = time.time(), (key, request.client.host if request.client else "?")
    h = [t for t in _hits.get(k, []) if now - t < window]
    if len(h) >= limit:
        raise HTTPException(429, "Too many attempts. Please wait a few minutes and try again.")
    _hits[k] = h + [now]


VOUCHER_CHARS = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"  # no 0/O/1/I/L, so codes are easy to read aloud or retype


def gen_voucher(conn):
    """Short customer-facing code, distinct from the internal MikroTik username. Retries on the rare collision."""
    for _ in range(5):
        code = "-".join("".join(secrets.choice(VOUCHER_CHARS) for _ in range(4)) for _ in range(2))
        if not db("SELECT 1 FROM sessions WHERE voucher_code=%s", (code,), one=True, conn=conn):
            return code
    raise HTTPException(500, "Could not generate a voucher code. Please try again.")


def expire_stale():
    """Orders never paid within 6 hours are closed so they don't sit in 'Pending' forever."""
    db("UPDATE payments SET status='Failed' WHERE status='Pending' AND created_at < now() - interval '6 hours'")
    db("UPDATE orders SET status='Failed' WHERE status='Pending' AND created_at < now() - interval '6 hours'")


# ---------------------------------------------------------------- Pesapal API v3
_pp = {"token": None, "exp": 0.0, "ipn_id": os.getenv("PESAPAL_IPN_ID")}
_pp_lock = threading.Lock()


def pp_call(method, path, **kw):
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if path != "/api/Auth/RequestToken":
        headers["Authorization"] = "Bearer " + pp_token()
    try:
        r = requests.request(method, PESAPAL_BASE + path, headers=headers, timeout=25, **kw)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError) as e:
        log.error("Pesapal %s failed: %s %s", path, e, getattr(getattr(e, "response", None), "text", ""))
        raise HTTPException(502, "The payment provider is not responding. Please try again in a moment.")


def pp_token():
    with _pp_lock:
        if _pp["token"] and time.time() < _pp["exp"]:
            return _pp["token"]
        d = pp_call("POST", "/api/Auth/RequestToken", json={"consumer_key": PESAPAL_KEY, "consumer_secret": PESAPAL_SECRET})
        if not d.get("token"):
            log.error("Pesapal auth rejected: %s", {k: v for k, v in d.items() if k != "token"})
            raise HTTPException(502, "Payments are temporarily unavailable. Please try again later.")
        _pp["token"], _pp["exp"] = d["token"], time.time() + 240  # Pesapal tokens last ~5 minutes
        return d["token"]


def pp_ipn_id():
    if not _pp["ipn_id"]:
        d = pp_call("POST", "/api/URLSetup/RegisterIPN", json={"url": PESAPAL_IPN_URL, "ipn_notification_type": "GET"})
        if not d.get("ipn_id"):
            log.error("Pesapal IPN registration failed: %s", d)
            raise HTTPException(502, "Payments are temporarily unavailable. Please try again later.")
        _pp["ipn_id"] = d["ipn_id"]
    return _pp["ipn_id"]


def pp_submit(ref, amount, description, cu):
    name = "TendoConnect Customer" if cu["full_name"] == "Hotspot customer" else cu["full_name"]
    first, _, last = name.partition(" ")
    digits = re.sub(r"\D", "", cu["phone"])
    local_phone = "0" + digits[3:] if digits.startswith("256") and len(digits) == 12 else digits
    d = pp_call("POST", "/api/Transactions/SubmitOrderRequest", json={
        "id": ref, "currency": "UGX", "amount": float(amount), "description": description[:100],
        "callback_url": PESAPAL_CALLBACK_URL, "notification_id": pp_ipn_id(),
        "billing_address": {"email_address": cu["email"] or "", "phone_number": local_phone, "country_code": "UG",
                            "first_name": first or "Hotspot", "last_name": last or "Customer",
                            "line_1": "", "line_2": "", "city": "", "state": "", "postal_code": "", "zip_code": ""}})
    if d.get("error") or not d.get("redirect_url") or not d.get("order_tracking_id"):
        log.error("Pesapal rejected order %s: %s", ref, d)
        raise HTTPException(502, "We could not start the payment. Please try again.")
    return d


def pp_status(tracking_id):
    return pp_call("GET", "/api/Transactions/GetTransactionStatus", params={"orderTrackingId": tracking_id})


def pp_method(s):
    s = (s or "").upper()
    return "Mobile Money" if any(k in s for k in ("MTN", "AIRTEL", "MPESA", "MOBILE")) else \
           "Card" if any(k in s for k in ("VISA", "MASTER", "CARD")) else "Other"


# ---------------------------------------------------------------- hotspot access (swap point)
class HotspotProvider:
    """Interface for controlling real internet access."""
    def create_user(self, username: str, profile: str, expires_at: datetime): raise NotImplementedError
    def disable_user(self, username: str): raise NotImplementedError


class ManualHotspotProvider(HotspotProvider):
    """Router NOT connected: paid sessions are recorded in the database only. Replace with a MikroTik provider."""
    def create_user(self, username, profile, expires_at): log.info("Paid session recorded - provision on router: %s (%s) until %s", username, profile, expires_at)
    def disable_user(self, username): log.info("Session ended - disable on router: %s", username)


def hotspot_provider() -> HotspotProvider:
    if os.getenv("MIKROTIK_HOST"):
        log.warning("MIKROTIK_HOST is set but the MikroTik provider is not implemented; using manual provisioning.")
    return ManualHotspotProvider()


# ---------------------------------------------------------------- SQL fragments
CUST = """SELECT c.id,c.full_name,c.phone,c.email,c.status,c.created_at,x.pkg AS current_package,x.expires_at AS package_expiry,
  COALESCE(p.spent,0) AS total_spent, COALESCE(p.n,0) AS purchases FROM customers c
  LEFT JOIN LATERAL (SELECT k.name AS pkg,s.expires_at FROM sessions s JOIN packages k ON k.id=s.package_id
     WHERE s.customer_id=c.id AND s.status='Active' AND s.expires_at>now() ORDER BY s.expires_at DESC LIMIT 1) x ON true
  LEFT JOIN LATERAL (SELECT sum(amount)::int AS spent,count(*)::int AS n FROM payments
     WHERE customer_id=c.id AND status='Completed') p ON true"""
PAY = """SELECT p.id,o.ref AS order_ref,p.customer_id,c.full_name AS customer,c.phone,k.name AS package,p.amount,p.currency,
  p.method,p.provider,p.provider_txn_id,p.status,p.created_at,p.paid_at FROM payments p JOIN orders o ON o.id=p.order_id
  JOIN customers c ON c.id=p.customer_id JOIN packages k ON k.id=p.package_id"""
SESS = """SELECT s.id,s.customer_id,c.full_name AS customer,k.name AS package,h.name AS hotspot,s.started_at,s.expires_at,
  CASE WHEN s.status='Active' AND s.expires_at<=now() THEN 'Expired' ELSE s.status END AS status,s.mikrotik_username,s.voucher_code
  FROM sessions s JOIN customers c ON c.id=s.customer_id JOIN packages k ON k.id=s.package_id
  LEFT JOIN hotspots h ON h.id=s.hotspot_id"""
LIVE = " s.status='Active' AND s.expires_at>now()"


def since(unit):  # start of today/week/month in Uganda time, as timestamptz
    return f"(date_trunc('{unit}', now() AT TIME ZONE 'Africa/Kampala') AT TIME ZONE 'Africa/Kampala')"


# ---------------------------------------------------------------- payment -> session workflow
def activate(c, p):
    """Runs ONLY after the provider verified payment. Marks paid, creates session + hotspot user. Caller holds the row lock."""
    o = db("SELECT * FROM orders WHERE id=%s", (p["order_id"],), one=True, conn=c)
    pk = db("SELECT * FROM packages WHERE id=%s", (o["package_id"],), one=True, conn=c)
    cu = db("SELECT * FROM customers WHERE id=%s", (o["customer_id"],), one=True, conn=c)
    hs = o["hotspot_id"] or (db("SELECT id FROM hotspots WHERE status='Online' ORDER BY id LIMIT 1", one=True, conn=c) or {}).get("id")
    now = datetime.now(timezone.utc)
    last = db("SELECT max(expires_at) AS m FROM sessions WHERE customer_id=%s AND status='Active'", (cu["id"],), one=True, conn=c)["m"]
    start = max(now, last) if last else now  # a new purchase extends an unexpired one
    expires = start + timedelta(**{pk["duration_unit"].lower(): pk["duration"]})
    username = "tc" + re.sub(r"\D", "", cu["phone"])
    voucher = gen_voucher(c)
    db("INSERT INTO sessions(order_id,customer_id,package_id,hotspot_id,started_at,expires_at,mikrotik_username,voucher_code) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
       (o["id"], cu["id"], pk["id"], hs, start, expires, username, voucher), conn=c)
    try:
        hotspot_provider().create_user(username, pk["name"], expires)
    except Exception:  # never lose a verified payment because the router step failed
        log.exception("Router provisioning failed for paid order %s", o["ref"])
    db("UPDATE payments SET status='Completed',paid_at=now() WHERE id=%s", (p["id"],), conn=c)
    db("UPDATE orders SET status='Paid' WHERE id=%s", (o["id"],), conn=c)
    db("UPDATE customers SET status='Active' WHERE id=%s AND status='Inactive'", (cu["id"],), conn=c)


def settle(pid, recheck=False):
    """Ask Pesapal (server to server) for the real status and act on it. Idempotent; the ONLY path that activates a package."""
    p = found(db("SELECT p.*,o.ref FROM payments p JOIN orders o ON o.id=p.order_id WHERE p.id=%s", (pid,), one=True), "Payment not found.")
    if not p["provider_txn_id"] or not (p["status"] == "Pending" or (recheck and p["status"] == "Completed")):
        return p["status"]
    st = pp_status(p["provider_txn_id"])
    desc, code = (st.get("payment_status_description") or "").upper(), st.get("status_code")
    if st.get("merchant_reference") not in (None, "", p["ref"]):
        log.critical("Pesapal reference mismatch on payment %s: %s", pid, st)
        return p["status"]
    with pool.connection() as c:
        p = db("SELECT * FROM payments WHERE id=%s FOR UPDATE", (pid,), one=True, conn=c)
        if p["status"] == "Pending":
            if desc == "COMPLETED" or code == 1:
                if (st.get("currency") or p["currency"]) != p["currency"] or float(st.get("amount") or 0) < p["amount"]:
                    log.critical("Pesapal amount/currency mismatch on payment %s: %s", pid, st)
                    return p["status"]
                db("UPDATE payments SET method=%s WHERE id=%s", (pp_method(st.get("payment_method")), pid), conn=c)
                activate(c, p)
            elif desc in ("FAILED", "REVERSED") or code in (2, 3):  # INVALID can still be an unpaid order, so it stays Pending
                db("UPDATE payments SET status='Failed' WHERE id=%s", (pid,), conn=c)
                db("UPDATE orders SET status='Failed' WHERE id=%s", (p["order_id"],), conn=c)
        elif p["status"] == "Completed" and (desc == "REVERSED" or code == 3):  # money returned to the customer
            db("UPDATE payments SET status='Refunded' WHERE id=%s", (pid,), conn=c)
            db("UPDATE sessions SET status='Terminated' WHERE order_id=%s", (p["order_id"],), conn=c)
        return db("SELECT status FROM payments WHERE id=%s", (pid,), one=True, conn=c)["status"]


# ---------------------------------------------------------------- health / settings
@app.get("/api/health", tags=["System"])
def health():
    """Plain liveness check — no database round-trip, so it stays fast and cheap to ping."""
    return {"status": "ok"}


@app.get("/api/settings/status", tags=["System"])
def settings_status(_=Depends(admin)):
    """Live check that Pesapal accepts our credentials. No secrets are returned."""
    try:
        pp_token()
        ok = True
    except HTTPException:
        ok = False
    return {"pesapal_environment": PESAPAL_ENV, "pesapal_credentials_ok": ok, "callback_url": PESAPAL_CALLBACK_URL,
            "ipn_url": PESAPAL_IPN_URL, "ipn_registered": bool(_pp["ipn_id"]), "router_provisioning": "manual"}


# ---------------------------------------------------------------- customers
@app.get("/api/customers", tags=["Customers"])
def customers_list(q: str = "", status: str = "", _=Depends(admin)):
    """Search by name/phone and filter by status."""
    return db(CUST + " WHERE (%s='' OR c.full_name ILIKE %s OR c.phone ILIKE %s) AND (%s='' OR c.status=%s) ORDER BY c.id DESC LIMIT 500",
              (q, f"%{q}%", f"%{q}%", status, status))


@app.post("/api/customers", status_code=201, tags=["Customers"])
def customers_create(b: CustomerIn, _=Depends(admin)):
    return db("INSERT INTO customers(full_name,phone,email,status) VALUES(%s,%s,%s,%s) RETURNING *", (b.full_name, b.phone, b.email, b.status), one=True)


@app.get("/api/customers/{cid}", tags=["Customers"])
def customers_get(cid: int, _=Depends(admin)):
    """Profile, statistics, current session and full transaction history."""
    c = found(db(CUST + " WHERE c.id=%s", (cid,), one=True), "Customer not found.")
    c["transactions"] = db(PAY + " WHERE p.customer_id=%s ORDER BY p.id DESC", (cid,))
    c["current_session"] = db(SESS + " WHERE s.customer_id=%s AND" + LIVE + " ORDER BY s.expires_at DESC LIMIT 1", (cid,), one=True)
    c["last_payment"] = next((t for t in c["transactions"] if t["status"] == "Completed"), None)
    return c


@app.put("/api/customers/{cid}", tags=["Customers"])
def customers_update(cid: int, b: CustomerIn, _=Depends(admin)):
    return found(db("UPDATE customers SET full_name=%s,phone=%s,email=%s,status=%s WHERE id=%s RETURNING *",
                    (b.full_name, b.phone, b.email, b.status, cid), one=True), "Customer not found.")


@app.delete("/api/customers/{cid}", tags=["Customers"])
def customers_delete(cid: int, _=Depends(admin)):
    """Soft delete: sets the customer to Inactive so history is kept."""
    found(db("UPDATE customers SET status='Inactive' WHERE id=%s RETURNING id", (cid,), one=True), "Customer not found.")
    return {"ok": True}


# ---------------------------------------------------------------- packages
@app.get("/api/packages", tags=["Packages"])
def packages_list(_=Depends(admin)):
    return db("SELECT * FROM packages ORDER BY duration_unit='Days', duration, id")


@app.get("/api/public/packages", tags=["Public"])
def packages_public():
    """Active packages for the customer purchase page."""
    return db("SELECT id,name,description,price,duration,duration_unit FROM packages WHERE active ORDER BY price")


@app.post("/api/packages", status_code=201, tags=["Packages"])
def packages_create(b: PackageIn, _=Depends(admin)):
    return db("INSERT INTO packages(name,description,price,duration,duration_unit,active) VALUES(%s,%s,%s,%s,%s,%s) RETURNING *",
              (b.name, b.description, b.price, b.duration, b.duration_unit, b.active), one=True)


@app.put("/api/packages/{pid}", tags=["Packages"])
def packages_update(pid: int, b: PackageIn, _=Depends(admin)):
    return found(db("UPDATE packages SET name=%s,description=%s,price=%s,duration=%s,duration_unit=%s,active=%s WHERE id=%s RETURNING *",
                    (b.name, b.description, b.price, b.duration, b.duration_unit, b.active, pid), one=True), "Package not found.")


@app.delete("/api/packages/{pid}", tags=["Packages"])
def packages_delete(pid: int, _=Depends(admin)):
    """Deletes an unused package; a package with orders is deactivated instead."""
    try:
        found(db("DELETE FROM packages WHERE id=%s RETURNING id", (pid,), one=True), "Package not found.")
        return {"ok": True}
    except psycopg.errors.ForeignKeyViolation:
        db("UPDATE packages SET active=false WHERE id=%s", (pid,))
        return {"ok": True, "deactivated": True}


# ---------------------------------------------------------------- orders & payments
def order_view(ref):
    o = found(db("""SELECT o.ref,o.amount,o.currency,o.status,o.created_at,k.name AS package,p.id AS payment_id,p.status AS payment_status
        FROM orders o JOIN packages k ON k.id=o.package_id JOIN payments p ON p.order_id=o.id WHERE o.ref=%s""", (ref,), one=True), "Order not found.")
    o["session"] = db(SESS + " JOIN orders o ON o.id=s.order_id WHERE o.ref=%s", (ref,), one=True)
    return o


@app.post("/api/orders", status_code=201, tags=["Orders"])
def orders_create(b: OrderIn, request: Request):
    """Public. Creates the order and a Pending payment, registers it with Pesapal and returns the hosted payment page URL."""
    throttle(request, "order", 8, 600)
    ref = "TC-" + secrets.token_hex(6).upper()
    with pool.connection() as c:
        pk = found(db("SELECT * FROM packages WHERE id=%s AND active", (b.package_id,), one=True, conn=c), "That package is not available.")
        if pk["price"] <= 0:
            raise HTTPException(400, "This package cannot be purchased online.")
        cu = db("INSERT INTO customers(full_name,phone) VALUES('Hotspot customer',%s) ON CONFLICT(phone) DO UPDATE SET phone=EXCLUDED.phone RETURNING *", (b.phone,), one=True, conn=c)
        if cu["status"] == "Suspended":
            raise HTTPException(403, "This account is suspended. Please contact TendoConnect support.")
        o = db("INSERT INTO orders(ref,customer_id,package_id,hotspot_id,amount) VALUES(%s,%s,%s,%s,%s) RETURNING *",
               (ref, cu["id"], pk["id"], b.hotspot_id, pk["price"]), one=True, conn=c)
        p = db("INSERT INTO payments(order_id,customer_id,package_id,amount,provider) VALUES(%s,%s,%s,%s,'Pesapal') RETURNING id",
               (o["id"], cu["id"], pk["id"], pk["price"]), one=True, conn=c)
    try:
        d = pp_submit(ref, pk["price"], f"TendoConnect {pk['name']}", cu)
    except Exception:
        db("UPDATE payments SET status='Failed' WHERE id=%s", (p["id"],))
        db("UPDATE orders SET status='Failed' WHERE id=%s", (o["id"],))
        raise
    db("UPDATE payments SET provider_txn_id=%s WHERE id=%s", (d["order_tracking_id"], p["id"]))
    return {**order_view(ref), "redirect_url": d["redirect_url"]}


@app.get("/api/orders/{ref}", tags=["Orders"])
def orders_get(ref: str):
    """Public, addressed by the unguessable order reference (returns no personal data)."""
    return order_view(ref.upper())


@app.get("/api/payments/status/{ref}", tags=["Payments"])
def payments_status(ref: str, request: Request):
    """Public, by order reference. Re-verifies a pending payment directly with Pesapal and activates it once confirmed."""
    throttle(request, "status", 90, 60)
    p = found(db("SELECT p.id FROM payments p JOIN orders o ON o.id=p.order_id WHERE o.ref=%s", (ref.upper(),), one=True), "Order not found.")
    settle(p["id"])
    return order_view(ref.upper())


@app.get("/api/payments", tags=["Payments"])
def payments_list(_=Depends(admin)):
    return db(PAY + " ORDER BY p.id DESC LIMIT 500")


@app.get("/api/payments/{pid}", tags=["Payments"])
def payments_get(pid: int, _=Depends(admin)):
    return found(db(PAY + " WHERE p.id=%s", (pid,), one=True), "Payment not found.")


@app.post("/api/payments/{pid}/confirm-cash", tags=["Payments"])
def payments_confirm_cash(pid: int, _=Depends(admin)):
    """Admin records a cash payment received in person, then activates the package."""
    with pool.connection() as c:
        p = found(db("SELECT * FROM payments WHERE id=%s FOR UPDATE", (pid,), one=True, conn=c), "Payment not found.")
        if p["status"] != "Pending":
            raise HTTPException(409, "Only pending payments can be confirmed.")
        db("UPDATE payments SET method='Cash',provider='Manual',provider_txn_id=%s WHERE id=%s", ("CASH-" + secrets.token_hex(4).upper(), pid), conn=c)
        activate(c, p)
    return {"ok": True}


def _pesapal_payment(request: Request):
    q = {k.lower(): v for k, v in request.query_params.items()}
    p = db("SELECT p.id,o.ref FROM payments p JOIN orders o ON o.id=p.order_id WHERE o.ref=%s OR p.provider_txn_id=%s",
           (q.get("ordermerchantreference", ""), q.get("ordertrackingid", "")), one=True)
    return p, q


@app.get("/api/pesapal/callback", include_in_schema=False)
def pesapal_callback(request: Request):
    """The customer lands here after paying. The redirect is NOT trusted: we verify with Pesapal, then show the receipt."""
    p, _ = _pesapal_payment(request)
    if not p:
        return RedirectResponse(f"{FRONTEND_URL}/", 302)
    try:
        settle(p["id"])
    except Exception:
        log.exception("Callback verification failed")  # the receipt page keeps re-checking
    return RedirectResponse(f"{FRONTEND_URL}/#/receipt/{p['ref']}", 302)


@app.get("/api/pesapal/ipn", include_in_schema=False)
def pesapal_ipn(request: Request):
    """Pesapal's server-to-server notification (registered as a GET IPN). Verifies, activates, and replies as Pesapal requires."""
    p, q = _pesapal_payment(request)
    echo = {"orderNotificationType": q.get("ordernotificationtype", ""), "orderTrackingId": q.get("ordertrackingid", ""),
            "orderMerchantReference": q.get("ordermerchantreference", "")}
    try:
        if p:
            settle(p["id"], recheck=True)
    except Exception:
        log.exception("IPN processing failed")
        return JSONResponse({**echo, "status": 500}, 500)  # non-200 makes Pesapal retry
    return {**echo, "status": 200}


# ---------------------------------------------------------------- withdrawals
WD = """SELECT w.id,w.admin_id,w.admin_username,w.amount,w.method,w.destination,w.notes,w.status,
  w.requested_at,w.processed_at,w.processed_by,w.reject_reason FROM withdrawals w"""


def _wallet():
    """Company funds ledger: completed revenue minus what's already been disbursed or is committed to pending requests."""
    row = db("""SELECT (SELECT COALESCE(sum(amount),0) FROM payments WHERE status='Completed')::int AS revenue,
                       (SELECT COALESCE(sum(amount),0) FROM withdrawals WHERE status='Paid')::int AS paid,
                       (SELECT COALESCE(sum(amount),0) FROM withdrawals WHERE status='Pending')::int AS pending""", one=True)
    row["available"] = row["revenue"] - row["paid"] - row["pending"]
    return row


@app.get("/api/withdrawals/balance", tags=["Withdrawals"])
def withdrawals_balance(_=Depends(admin)):
    return _wallet()


@app.get("/api/withdrawals/pending-count", tags=["Withdrawals"])
def withdrawals_pending_count(a=Depends(admin)):
    """Powers the sidebar notification badge that tells a super admin a disbursement is waiting on them."""
    if a.get("role") != "SuperAdmin":
        return {"count": 0}
    return {"count": db("SELECT count(*)::int AS n FROM withdrawals WHERE status='Pending'", one=True)["n"]}


@app.get("/api/withdrawals", tags=["Withdrawals"])
def withdrawals_list(a=Depends(admin)):
    """Admins see only their own requests; super admins see everyone's, so they can act on pending ones."""
    if a.get("role") == "SuperAdmin":
        return db(WD + " ORDER BY w.id DESC LIMIT 500")
    return db(WD + " WHERE w.admin_id=%s ORDER BY w.id DESC LIMIT 500", (a["aid"],))


@app.post("/api/withdrawals", status_code=201, tags=["Withdrawals"])
def withdrawals_create(b: WithdrawalIn, a=Depends(admin)):
    """Any admin requests a withdrawal of company funds. A super admin is notified and must approve it to disburse."""
    avail = _wallet()["available"]
    if b.amount > avail:
        raise HTTPException(400, f"That's more than the available balance of UGX {avail:,}.")
    return db("""INSERT INTO withdrawals(admin_id,admin_username,amount,method,destination,notes)
               VALUES(%s,%s,%s,%s,%s,%s) RETURNING *""",
              (a["aid"], a["sub"], b.amount, b.method, b.destination, b.notes), one=True)


@app.post("/api/withdrawals/{wid}/approve", tags=["Withdrawals"])
def withdrawals_approve(wid: int, a=Depends(super_admin)):
    """Super admin confirms the funds have been physically disbursed to the requesting admin."""
    found(db("""UPDATE withdrawals SET status='Paid',processed_at=now(),processed_by=%s
               WHERE id=%s AND status='Pending' RETURNING id""", (a["sub"], wid), one=True),
          "Only pending requests can be approved (or the request was not found).")
    return {"ok": True}


@app.post("/api/withdrawals/{wid}/reject", tags=["Withdrawals"])
def withdrawals_reject(wid: int, b: RejectIn, a=Depends(super_admin)):
    found(db("""UPDATE withdrawals SET status='Rejected',processed_at=now(),processed_by=%s,reject_reason=%s
               WHERE id=%s AND status='Pending' RETURNING id""", (a["sub"], b.reason, wid), one=True),
          "Only pending requests can be rejected (or the request was not found).")
    return {"ok": True}


# ---------------------------------------------------------------- hotspots & sessions
@app.get("/api/hotspots", tags=["Hotspots"])
def hotspots_list(_=Depends(admin)):
    return db("SELECT * FROM hotspots ORDER BY id")


@app.post("/api/hotspots", status_code=201, tags=["Hotspots"])
def hotspots_create(b: HotspotIn, _=Depends(admin)):
    return db("INSERT INTO hotspots(name,location,status,device_id) VALUES(%s,%s,%s,%s) RETURNING *", (b.name, b.location, b.status, b.device_id), one=True)


@app.put("/api/hotspots/{hid}", tags=["Hotspots"])
def hotspots_update(hid: int, b: HotspotIn, _=Depends(admin)):
    return found(db("UPDATE hotspots SET name=%s,location=%s,status=%s,device_id=%s WHERE id=%s RETURNING *",
                    (b.name, b.location, b.status, b.device_id, hid), one=True), "Hotspot not found.")


@app.get("/api/sessions", tags=["Sessions"])
def sessions_list(_=Depends(admin)):
    """Status is derived from expires_at, so expiry is always correct."""
    return db(SESS + " ORDER BY s.id DESC LIMIT 500")


@app.get("/api/sessions/active", tags=["Sessions"])
def sessions_active(_=Depends(admin)):
    return db(SESS + " WHERE" + LIVE + " ORDER BY s.expires_at")


@app.post("/api/sessions/{sid}/terminate", tags=["Sessions"])
def sessions_terminate(sid: int, _=Depends(admin)):
    s = found(db("UPDATE sessions SET status='Terminated' WHERE id=%s RETURNING mikrotik_username", (sid,), one=True), "Session not found.")
    hotspot_provider().disable_user(s["mikrotik_username"])
    return {"ok": True}


# ---------------------------------------------------------------- dashboard, reports, portal
@app.get("/api/dashboard/stats", tags=["Dashboard"])
def dashboard_stats(_=Depends(admin)):
    expire_stale()
    return db(f"""SELECT (SELECT count(*) FROM customers)::int AS total_customers,
      (SELECT count(*) FROM customers WHERE status='Active')::int AS active_customers,
      (SELECT COALESCE(sum(amount),0) FROM payments WHERE status='Completed' AND paid_at>={since('day')})::int AS revenue_today,
      (SELECT COALESCE(sum(amount),0) FROM payments WHERE status='Completed')::int AS revenue_total,
      (SELECT count(*) FROM sessions s WHERE{LIVE})::int AS active_sessions,
      (SELECT count(*) FROM payments WHERE status='Pending')::int AS pending_payments,
      (SELECT count(*) FROM withdrawals WHERE status='Pending')::int AS pending_withdrawals""", one=True)


@app.get("/api/reports", tags=["Dashboard"])
def reports(_=Depends(admin)):
    r = db(f"""SELECT (SELECT COALESCE(sum(amount),0) FROM payments WHERE status='Completed' AND paid_at>={since('day')})::int AS revenue_today,
      (SELECT COALESCE(sum(amount),0) FROM payments WHERE status='Completed' AND paid_at>={since('week')})::int AS revenue_week,
      (SELECT COALESCE(sum(amount),0) FROM payments WHERE status='Completed' AND paid_at>={since('month')})::int AS revenue_month,
      (SELECT COALESCE(sum(amount),0) FROM payments WHERE status='Completed')::int AS revenue_total,
      (SELECT count(*) FROM customers)::int AS customers, (SELECT count(*) FROM payments WHERE status='Completed')::int AS purchases""", one=True)
    top = db("SELECT k.name,count(*)::int AS n FROM payments p JOIN packages k ON k.id=p.package_id WHERE p.status='Completed' GROUP BY k.name ORDER BY n DESC LIMIT 1", one=True)
    r["top_package"] = top["name"] if top else None
    r["payment_counts"] = {x["status"]: x["n"] for x in db("SELECT status,count(*)::int AS n FROM payments GROUP BY status")}
    return r


@app.post("/api/portal/lookup", tags=["Public"])
def portal_lookup(b: PortalIn, request: Request):
    """Customer portal. Needs the phone number AND a receipt code from one of that customer's purchases."""
    throttle(request, "portal", 10, 600)
    c = found(db("SELECT c.id,c.full_name FROM customers c JOIN orders o ON o.customer_id=c.id WHERE c.phone=%s AND o.ref=%s",
                 (b.phone, b.receipt.strip().upper()), one=True), "No match. Check your phone number and a receipt code from one of your purchases.")
    return {"name": c["full_name"],
            "current_session": db(SESS + " WHERE s.customer_id=%s AND" + LIVE + " ORDER BY s.expires_at DESC LIMIT 1", (c["id"],), one=True),
            "purchases": db("""SELECT o.ref,k.name AS package,p.amount,p.currency,p.method,p.status,p.created_at,
                                s.voucher_code,s.expires_at AS voucher_expires,
                                CASE WHEN s.status='Active' AND s.expires_at<=now() THEN 'Expired' ELSE s.status END AS voucher_status
                                FROM payments p JOIN orders o ON o.id=p.order_id JOIN packages k ON k.id=p.package_id
                                LEFT JOIN sessions s ON s.order_id=o.id
                                WHERE p.customer_id=%s ORDER BY p.id DESC LIMIT 100""", (c["id"],))}


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(Path(__file__).parent / "index.html")
