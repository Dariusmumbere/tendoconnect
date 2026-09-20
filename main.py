"""TendoConnect Technologies - Customer & Hotspot Management API (single-file backend)."""
import logging, os, re, secrets
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal, Optional

import bcrypt, jwt, psycopg, psycopg_pool
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from pydantic import BaseModel, Field, field_validator

load_dotenv()
log = logging.getLogger("tendoconnect")
DATABASE_URL, SECRET_KEY = os.getenv("DATABASE_URL"), os.getenv("SECRET_KEY")
PAYMENT_MODE = os.getenv("PAYMENT_MODE", "mock")  # "mock" | "pesapal" (pesapal not implemented yet)
if not DATABASE_URL or not SECRET_KEY:
    raise RuntimeError("DATABASE_URL and SECRET_KEY must be set (see .env.example).")

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
  mikrotik_username TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS admins(id SERIAL PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS ix_orders_customer ON orders(customer_id);
CREATE INDEX IF NOT EXISTS ix_payments_customer ON payments(customer_id, status);
CREATE INDEX IF NOT EXISTS ix_sessions_customer ON sessions(customer_id, expires_at);
"""
SEED_PACKAGES = [("1 Hour", 500, 1, "Hours"), ("3 Hours", 1000, 3, "Hours"), ("12 Hours", 1500, 12, "Hours"),
                 ("24 Hours", 2000, 24, "Hours"), ("7 Days", 7000, 7, "Days"), ("30 Days", 20000, 30, "Days")]


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
    if not db("SELECT 1 FROM hotspots LIMIT 1", one=True):
        db("INSERT INTO hotspots(name,location,status) VALUES('TendoConnect - Main Hotspot','Kampala','Online')")
    yield
    pool.close()


app = FastAPI(title="TendoConnect Technologies API", version="1.0.0", lifespan=lifespan,
              description="Customers, packages, orders, payments, hotspots and sessions. "
                          "Payments run in MOCK mode; Pesapal and MikroTik are prepared but NOT integrated.")
origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["*"], allow_headers=["*"])


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
        return jwt.decode(cred.credentials, SECRET_KEY, algorithms=["HS256"])["sub"]
    except Exception:
        raise HTTPException(401, "Please sign in again.")


class Login(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=1, max_length=200)


class Setup(Login):
    password: str = Field(min_length=10, max_length=200)
    setup_key: str


def token_for(username):
    exp = datetime.now(timezone.utc) + timedelta(hours=8)
    return jwt.encode({"sub": username, "exp": exp}, SECRET_KEY, algorithm="HS256")


@app.get("/api/auth/status", tags=["Auth"])
def auth_status():
    """Tells the login screen whether the first admin still has to be created."""
    return {"setup_required": db("SELECT 1 FROM admins LIMIT 1", one=True) is None}


@app.post("/api/auth/setup", status_code=201, tags=["Auth"])
def auth_setup(b: Setup):
    """Create the first admin. Only works while no admin exists and requires SECRET_KEY as setup_key."""
    if db("SELECT 1 FROM admins LIMIT 1", one=True):
        raise HTTPException(409, "An admin already exists.")
    if not secrets.compare_digest(b.setup_key, SECRET_KEY):
        raise HTTPException(403, "Invalid setup key.")
    h = bcrypt.hashpw(b.password.encode(), bcrypt.gensalt()).decode()
    db("INSERT INTO admins(username,password_hash) VALUES(%s,%s)", (b.username.lower(), h))
    return {"token": token_for(b.username.lower())}


@app.post("/api/auth/login", tags=["Auth"])
def auth_login(b: Login):
    a = db("SELECT * FROM admins WHERE username=%s", (b.username.lower(),), one=True)
    if not a or not bcrypt.checkpw(b.password.encode(), a["password_hash"].encode()):
        raise HTTPException(401, "Wrong username or password.")
    return {"token": token_for(a["username"])}


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


class MockPay(BaseModel):
    order_ref: str
    method: Literal["Mobile Money", "Card", "Cash", "Other"]
    outcome: Literal["success", "failure"] = "success"


class PortalIn(BaseModel):
    phone: str
    receipt: str = Field(min_length=4, max_length=40)

    @field_validator("phone")
    @classmethod
    def _phone(cls, v):
        return norm_phone(v)


# ---------------------------------------------------------------- providers (swap points)
class PaymentProvider:
    """Interface. Implement PesapalProvider later without touching the order/session logic."""
    def create_order(self, order: dict) -> dict: raise NotImplementedError
    def verify(self, payment: dict) -> str: raise NotImplementedError  # -> Completed|Failed|Cancelled|Pending


class MockPaymentProvider(PaymentProvider):
    """Demo only. The mock endpoint stamps MOCK-OK-/MOCK-FAIL- ids; verify() reads that 'provider record'."""
    def create_order(self, order): return {"redirect_url": None}

    def verify(self, payment):
        t = payment.get("provider_txn_id") or ""
        return "Completed" if t.startswith("MOCK-OK-") else "Failed" if t.startswith("MOCK-FAIL-") else "Pending"


class PesapalProvider(PaymentProvider):
    """NOT IMPLEMENTED. Fill in using PESAPAL_* env vars: auth token -> SubmitOrderRequest -> GetTransactionStatus."""
    def create_order(self, order): raise HTTPException(501, "Pesapal is not integrated yet.")
    def verify(self, payment): raise HTTPException(501, "Pesapal is not integrated yet.")


PAYMENT_PROVIDERS = {"Mock": MockPaymentProvider, "Pesapal": PesapalProvider}


class HotspotProvider:
    """Interface for controlling real internet access."""
    def create_user(self, username: str, profile: str, expires_at: datetime): raise NotImplementedError
    def disable_user(self, username: str): raise NotImplementedError


class MockHotspotProvider(HotspotProvider):
    def create_user(self, username, profile, expires_at): log.info("[mock hotspot] user %s (%s) until %s", username, profile, expires_at)
    def disable_user(self, username): log.info("[mock hotspot] disable %s", username)


class MikroTikProvider(HotspotProvider):
    """NOT IMPLEMENTED. Uses MIKROTIK_HOST/USERNAME/PASSWORD/PORT (RouterOS API); credentials stay server-side."""
    def create_user(self, username, profile, expires_at): raise NotImplementedError("MikroTik is not integrated yet.")
    def disable_user(self, username): raise NotImplementedError("MikroTik is not integrated yet.")


def hotspot_provider() -> HotspotProvider:
    return MikroTikProvider() if os.getenv("MIKROTIK_HOST") else MockHotspotProvider()


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
  CASE WHEN s.status='Active' AND s.expires_at<=now() THEN 'Expired' ELSE s.status END AS status,s.mikrotik_username
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
    hotspot_provider().create_user(username, pk["name"], expires)
    db("INSERT INTO sessions(order_id,customer_id,package_id,hotspot_id,started_at,expires_at,mikrotik_username) VALUES(%s,%s,%s,%s,%s,%s,%s)",
       (o["id"], cu["id"], pk["id"], hs, start, expires, username), conn=c)
    db("UPDATE payments SET status='Completed',paid_at=now() WHERE id=%s", (p["id"],), conn=c)
    db("UPDATE orders SET status='Paid' WHERE id=%s", (o["id"],), conn=c)
    db("UPDATE customers SET status='Active' WHERE id=%s AND status='Inactive'", (cu["id"],), conn=c)


def settle(pid):
    """Verify with the provider (server-side) and activate if - and only if - it is Completed. Idempotent."""
    with pool.connection() as c:
        p = found(db("SELECT * FROM payments WHERE id=%s FOR UPDATE", (pid,), one=True, conn=c), "Payment not found.")
        if p["status"] == "Pending":
            status = PAYMENT_PROVIDERS[p["provider"]]().verify(p)
            if status == "Completed":
                activate(c, p)
            elif status in ("Failed", "Cancelled"):
                db("UPDATE payments SET status=%s WHERE id=%s", (status, pid), conn=c)
                db("UPDATE orders SET status=%s WHERE id=%s", (status, p["order_id"]), conn=c)
        return db("SELECT id,status FROM payments WHERE id=%s", (pid,), one=True, conn=c)


# ---------------------------------------------------------------- health / settings
@app.get("/api/health", tags=["System"])
def health():
    db("SELECT 1")
    return {"status": "ok", "database": "up"}


@app.get("/api/settings/status", tags=["System"])
def settings_status(_=Depends(admin)):
    return {"payment_mode": PAYMENT_MODE,
            "pesapal_configured": bool(os.getenv("PESAPAL_CONSUMER_KEY") and os.getenv("PESAPAL_CONSUMER_SECRET")),
            "pesapal_integrated": False, "mikrotik_configured": bool(os.getenv("MIKROTIK_HOST")), "mikrotik_integrated": False}


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
def orders_create(b: OrderIn):
    """Public. Step 1 of the flow: creates the customer (if new), an order and a Pending payment."""
    provider = "Mock" if PAYMENT_MODE == "mock" else "Pesapal"
    ref = "TC-" + secrets.token_hex(6).upper()
    with pool.connection() as c:
        pk = found(db("SELECT * FROM packages WHERE id=%s AND active", (b.package_id,), one=True, conn=c), "That package is not available.")
        cu = db("INSERT INTO customers(full_name,phone) VALUES('Hotspot customer',%s) ON CONFLICT(phone) DO UPDATE SET phone=EXCLUDED.phone RETURNING *", (b.phone,), one=True, conn=c)
        if cu["status"] == "Suspended":
            raise HTTPException(403, "This account is suspended. Please contact TendoConnect support.")
        o = db("INSERT INTO orders(ref,customer_id,package_id,hotspot_id,amount) VALUES(%s,%s,%s,%s,%s) RETURNING *",
               (ref, cu["id"], pk["id"], b.hotspot_id, pk["price"]), one=True, conn=c)
        db("INSERT INTO payments(order_id,customer_id,package_id,amount,provider) VALUES(%s,%s,%s,%s,%s)", (o["id"], cu["id"], pk["id"], pk["price"], provider), conn=c)
        PAYMENT_PROVIDERS[provider]().create_order(o)
    return order_view(ref)


@app.get("/api/orders/{ref}", tags=["Orders"])
def orders_get(ref: str):
    """Public, addressed by the unguessable order reference (returns no personal data)."""
    return order_view(ref.upper())


@app.post("/api/payments/mock", tags=["Payments"])
def payments_mock(b: MockPay):
    """MOCK ONLY (PAYMENT_MODE=mock). Simulates the provider; the backend still verifies before activating."""
    if PAYMENT_MODE != "mock":
        raise HTTPException(403, "Mock payments are disabled.")
    p = found(db("SELECT p.* FROM payments p JOIN orders o ON o.id=p.order_id WHERE o.ref=%s", (b.order_ref.upper(),), one=True), "Order not found.")
    if p["status"] != "Pending":
        raise HTTPException(409, "This payment was already processed.")
    txn = f"MOCK-{'OK' if b.outcome == 'success' else 'FAIL'}-{secrets.token_hex(4).upper()}"
    db("UPDATE payments SET method=%s,provider_txn_id=%s WHERE id=%s", (b.method, txn, p["id"]))
    settle(p["id"])
    return order_view(b.order_ref.upper())


@app.get("/api/payments/status/{pid}", tags=["Payments"])
def payments_status(pid: int):
    """Re-verifies a pending payment with its provider and returns only the status."""
    return settle(pid)


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


@app.get("/api/pesapal/callback", tags=["Pesapal (placeholder)"])
def pesapal_callback():
    """TODO: Pesapal redirects the customer here. Look up the order, call settle(); never trust the redirect itself."""
    raise HTTPException(501, "Pesapal is not integrated yet.")


@app.post("/api/pesapal/ipn", tags=["Pesapal (placeholder)"])
def pesapal_ipn(request: Request):
    """TODO: IPN webhook. Take the tracking id, call PesapalProvider.verify() via settle(), then reply as Pesapal requires."""
    raise HTTPException(501, "Pesapal is not integrated yet.")


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
    return db(f"""SELECT (SELECT count(*) FROM customers)::int AS total_customers,
      (SELECT count(*) FROM customers WHERE status='Active')::int AS active_customers,
      (SELECT COALESCE(sum(amount),0) FROM payments WHERE status='Completed' AND paid_at>={since('day')})::int AS revenue_today,
      (SELECT COALESCE(sum(amount),0) FROM payments WHERE status='Completed')::int AS revenue_total,
      (SELECT count(*) FROM sessions s WHERE{LIVE})::int AS active_sessions,
      (SELECT count(*) FROM payments WHERE status='Pending')::int AS pending_payments""", one=True)


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
def portal_lookup(b: PortalIn):
    """Customer portal. Needs the phone number AND a receipt code from one of that customer's purchases."""
    c = found(db("SELECT c.id,c.full_name FROM customers c JOIN orders o ON o.customer_id=c.id WHERE c.phone=%s AND o.ref=%s",
                 (b.phone, b.receipt.strip().upper()), one=True), "No match. Check your phone number and a receipt code from one of your purchases.")
    return {"name": c["full_name"],
            "current_session": db(SESS + " WHERE s.customer_id=%s AND" + LIVE + " ORDER BY s.expires_at DESC LIMIT 1", (c["id"],), one=True),
            "purchases": db("SELECT o.ref,k.name AS package,p.amount,p.currency,p.method,p.status,p.created_at FROM payments p "
                            "JOIN orders o ON o.id=p.order_id JOIN packages k ON k.id=p.package_id WHERE p.customer_id=%s ORDER BY p.id DESC LIMIT 100", (c["id"],))}


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(Path(__file__).parent / "index.html")
