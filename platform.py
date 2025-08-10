#!/usr/bin/env python3
"""
CryptoPirate Platform — FastAPI multi‑tenant backend (MVP) with SSL‑safe fallback + Local HTML Report

What’s new
- **Local HTML report** that is generated even when `ssl` / FastAPI aren’t available.
- Friendly, single‑file report with auto‑refresh, totals per user, trade table, and 5% platform fee column.
- CLI: `--report-path` (default `./cryptopirate_report.html`).
- Headless demo and the simulated engine **update the report** automatically after state changes.
- Added tests to ensure report generation works.

Why this structure?
Your environment threw `ModuleNotFoundError: No module named 'ssl'` when importing FastAPI.
We now lazily import FastAPI only if `ssl` is available, and otherwise run a headless demo. Either way, the
**core services and the HTML report** work.

Quick start (dev without FastAPI):
  pip install sqlalchemy passlib[bcrypt] python-dotenv pydantic[dotenv] itsdangerous cryptography
  export APP_FERNET_KEY=$(python - <<'PY'\nfrom cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\nPY)
  export JWT_SECRET=change-me
  python platform.py --serve --report-path ./cryptopirate_report.html
  # Open the generated HTML file in your browser; it auto-refreshes every 5s.

ENV (.env supported)
  APP_FERNET_KEY   (required) — base64 urlsafe key used by Fernet
  JWT_SECRET       (required) — signing secret for tokens
  DATABASE_URL     sqlite+aiosqlite:///./cp.db (default)
  ENGINE_RUN       1 to run the simulated engine (default 1)
  PROFIT_SHARE_BPS 500 (5% of positive net)
  REPORT_PATH      ./cryptopirate_report.html (default if not overridden by CLI)
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime
from typing import Optional, List, Any

from pydantic import BaseModel, Field
from passlib.context import CryptContext
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey, Text, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from itsdangerous import URLSafeTimedSerializer
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# -------- Optional web stack (guarded on ssl) --------
SSL_OK = True
try:  # some sandboxes lack OpenSSL bindings entirely
    import ssl as _ssl  # noqa: F401
except Exception:
    SSL_OK = False

FASTAPI_OK = False
if SSL_OK:
    try:
        from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
        from fastapi.responses import HTMLResponse
        from fastapi.security import OAuth2PasswordRequestForm
        FASTAPI_OK = True
    except Exception:
        FASTAPI_OK = False

load_dotenv()

# --- Config ---
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./cp.db")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
FERNET_KEY = os.getenv("APP_FERNET_KEY")
if not FERNET_KEY:
    raise RuntimeError("APP_FERNET_KEY is required. Generate one with cryptography.Fernet.generate_key().")
fernet = Fernet(FERNET_KEY.encode())
PROFIT_SHARE_BPS = int(os.getenv("PROFIT_SHARE_BPS", "500"))  # 5%
ENGINE_RUN = os.getenv("ENGINE_RUN", "1") == "1"
REPORT_PATH_DEFAULT = os.getenv("REPORT_PATH", "./cryptopirate_report.html")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
sign = URLSafeTimedSerializer(JWT_SECRET)

# --- DB setup ---
Base = declarative_base()
engine = create_async_engine(DATABASE_URL, future=True, echo=False)
SessionLocal = sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

# --- Models ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    is_admin = Column(Boolean, default=False)
    api_keys = relationship("ApiCredential", back_populates="user", cascade="all,delete-orphan")
    trades = relationship("Trade", back_populates="user", cascade="all,delete-orphan")

class ApiCredential(Base):
    __tablename__ = "api_credentials"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    exchange = Column(String, default="coinbase")
    name = Column(String, default="primary")
    enc_payload = Column(Text, nullable=False)  # encrypted JSON: {key, secret, passphrase}
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="api_keys")

class Trade(Base):
    __tablename__ = "trades"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True)
    triangle = Column(String)   # e.g., BTC-USD -> ETH-BTC -> ETH-USD
    notional_usd = Column(Float, default=0.0)
    net_usd = Column(Float, default=0.0)   # realized after fees & slippage
    platform_fee_usd = Column(Float, default=0.0)  # 5% of positive net
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="trades")

# --- Schemas (shared) ---
class SignupIn(BaseModel):
    email: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class ApiKeyIn(BaseModel):
    exchange: str = Field(default="coinbase")
    name: str = Field(default="primary")
    key: str
    secret: str
    passphrase: Optional[str] = None

class ApiKeyOut(BaseModel):
    id: int
    exchange: str
    name: str
    created_at: datetime

class TradeOut(BaseModel):
    id: int
    triangle: str
    notional_usd: float
    net_usd: float
    platform_fee_usd: float
    created_at: datetime

class MeOut(BaseModel):
    id: int
    email: str
    created_at: datetime
    pnl_total_usd: float

# --- Service layer (usable by web routes and tests) ---
async def db_init() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)

def verify_password(pw: str, hashed: str) -> bool:
    return pwd_context.verify(pw, hashed)

def create_token(user_id: int, email: str) -> str:
    return sign.dumps({"uid": user_id, "em": email})

async def svc_signup(db: AsyncSession, email: str, password: str) -> str:
    exists = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if exists:
        raise ValueError("email_in_use")
    u = User(email=email, password_hash=hash_password(password))
    db.add(u)
    await db.commit(); await db.refresh(u)
    return create_token(u.id, u.email)

async def svc_login(db: AsyncSession, email: str, password: str) -> str:
    u = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if not u or not verify_password(password, u.password_hash):
        raise ValueError("bad_credentials")
    return create_token(u.id, u.email)

async def svc_user_from_token(db: AsyncSession, token: str) -> User:
    try:
        data = sign.loads(token, max_age=60*60*24*7)
    except Exception:
        raise ValueError("bad_token")
    uid = int(data["uid"]) if isinstance(data, dict) else int(data.get("uid"))
    u = await db.get(User, uid)
    if not u:
        raise ValueError("no_user")
    return u

async def svc_add_api_key(db: AsyncSession, user: User, payload: ApiKeyIn) -> ApiKeyOut:
    enc = fernet.encrypt((
        __import__("json").dumps({"key": payload.key, "secret": payload.secret, "passphrase": payload.passphrase})
    ).encode()).decode()
    rec = ApiCredential(user_id=user.id, exchange=payload.exchange, name=payload.name, enc_payload=enc)
    db.add(rec)
    await db.commit(); await db.refresh(rec)
    return ApiKeyOut(id=rec.id, exchange=rec.exchange, name=rec.name, created_at=rec.created_at)

async def svc_list_api_keys(db: AsyncSession, user: User) -> List[ApiKeyOut]:
    rows = (await db.execute(select(ApiCredential).where(ApiCredential.user_id == user.id))).scalars().all()
    return [ApiKeyOut(id=r.id, exchange=r.exchange, name=r.name, created_at=r.created_at) for r in rows]

async def svc_submit_fill(db: AsyncSession, user: User, triangle: str, notional_usd: float, net_usd: float) -> TradeOut:
    fee = max(0.0, net_usd * (PROFIT_SHARE_BPS / 10_000.0))
    rec = Trade(user_id=user.id, triangle=triangle, notional_usd=notional_usd, net_usd=net_usd, platform_fee_usd=fee)
    db.add(rec)
    await db.commit(); await db.refresh(rec)
    return TradeOut(id=rec.id, triangle=rec.triangle, notional_usd=rec.notional_usd, net_usd=rec.net_usd, platform_fee_usd=rec.platform_fee_usd, created_at=rec.created_at)

async def svc_me(db: AsyncSession, user: User) -> MeOut:
    rows = (await db.execute(select(Trade).where(Trade.user_id == user.id))).scalars().all()
    pnl = sum(t.net_usd - t.platform_fee_usd for t in rows)
    return MeOut(id=user.id, email=user.email, created_at=user.created_at, pnl_total_usd=pnl)

# --- Local HTML report (no server required) ---
REPORT_PATH: str = REPORT_PATH_DEFAULT

async def generate_html_report(path: Optional[str] = None) -> str:
    """Create a pretty, self‑contained HTML report for all users and trades.
    Returns the path written.
    """
    out_path = path or REPORT_PATH
    async with SessionLocal() as db:
        users = (await db.execute(select(User))).scalars().all()
        rows_by_user = {}
        for u in users:
            trades = (await db.execute(select(Trade).where(Trade.user_id == u.id).order_by(Trade.id.desc()))).scalars().all()
            pnl = sum(t.net_usd - t.platform_fee_usd for t in trades)
            rows_by_user[u] = (trades, pnl)
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    def row_html(t: Trade) -> str:
        return (
            f"<tr><td>{t.created_at.strftime('%H:%M:%S')}</td>"
            f"<td><code>{t.triangle}</code></td>"
            f"<td>${t.notional_usd:,.2f}</td>"
            f"<td>${t.net_usd:,.2f}</td>"
            f"<td>${t.platform_fee_usd:,.2f}</td></tr>"
        )

    cards = []
    for u, (trades, pnl) in rows_by_user.items():
        trs = "".join(row_html(t) for t in trades) or "<tr><td colspan=5 style='color:#94a3b8'>No trades yet</td></tr>"
        cards.append(
            f"""
            <section class="card">
              <div class="card-h">
                <div>
                  <div class="k">User</div>
                  <div class="v">{u.email}</div>
                </div>
                <div>
                  <div class="k">Total PnL (after 5%)</div>
                  <div class="v {('good' if pnl>=0 else 'bad')}">${pnl:,.2f}</div>
                </div>
              </div>
              <table>
                <thead><tr><th>Time</th><th>Triangle</th><th>Notional</th><th>Net</th><th>Platform 5%</th></tr></thead>
                <tbody>{trs}</tbody>
              </table>
            </section>
            """
        )

    html = f"""
<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>CryptoPirate Report</title>
<meta http-equiv="refresh" content="5"> <!-- auto refresh every 5s -->
<style>
  :root{{--bg:#0b1020;--fg:#e6eefc;--muted:#94a3b8;--card:#121a33;--ok:#16a34a;--bad:#dc2626}}
  body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu}}
  header{{padding:16px 20px;border-bottom:1px solid #1f2a44;display:flex;justify-content:space-between;align-items:center}}
  .wrap{{padding:20px;display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}}
  .card{{background:var(--card);padding:16px;border-radius:14px;box-shadow:0 6px 28px rgba(0,0,0,.25)}}
  .card-h{{display:flex;justify-content:space-between;gap:12px;margin-bottom:8px}}
  .k{{font-size:12px;color:var(--muted)}} .v{{font-size:22px;font-weight:700}}
  .good{{color:var(--ok)}} .bad{{color:var(--bad)}}
  table{{width:100%;border-collapse:collapse;margin-top:8px}}
  td,th{{padding:8px;border-bottom:1px solid #1f2a44;text-align:left}}
  tr:last-child td, tr:last-child th{{border-bottom:none}}
  code{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#cbd5e1}}
  footer{{padding:12px 20px;color:var(--muted)}}
  .mono{{font-family:ui-monospace,Menlo,Consolas,monospace}}
  .pill{{display:inline-block;padding:4px 8px;border-radius:999px;background:#16203e;color:#cbd5e1;margin-left:8px}}
</style>
<header>
  <h1>🏴‍☠️ CryptoPirate — Local Report</h1>
  <div class="mono">Updated: {now} <span class="pill">auto‑refresh 5s</span></div>
</header>
<div class="wrap">
  {''.join(cards) if cards else '<section class="card"><div class="k">No users yet</div></section>'}
</div>
<footer class="mono">Profit share = 5% of positive net per trade. Figures shown are after fees.</footer>
"""
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    return out_path

# --- FastAPI app (only if ssl & imports are OK) ---
if FASTAPI_OK:
    app = FastAPI(title="CryptoPirate Platform", version="0.1.2")

    from fastapi import Request

    async def current_user_from_request(request: Request, db: AsyncSession) -> User:
        token = None
        auth = request.headers.get("Authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
        if token is None:
            token = request.query_params.get("token")
        if not token:
            raise HTTPException(status_code=401, detail="Missing token")
        try:
            return await svc_user_from_token(db, token)
        except ValueError:
            raise HTTPException(status_code=401, detail="Invalid or expired token")

    @app.on_event("startup")
    async def on_startup() -> None:
        await db_init()
        await generate_html_report()  # write initial report
        if ENGINE_RUN:
            asyncio.create_task(simulated_engine_loop())

    @app.post("/signup", response_model=TokenOut)
    async def signup(data: SignupIn, db: AsyncSession = Depends(lambda: SessionLocal())):
        try:
            token = await svc_signup(db, data.email, data.password)
        except ValueError:
            raise HTTPException(409, "Email already in use")
        await generate_html_report()
        return TokenOut(access_token=token)

    @app.post("/login", response_model=TokenOut)
    async def login(form: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(lambda: SessionLocal())):
        try:
            token = await svc_login(db, form.username, form.password)
        except ValueError:
            raise HTTPException(400, "Invalid credentials")
        return TokenOut(access_token=token)

    @app.post("/api-keys", response_model=ApiKeyOut)
    async def add_api_key(payload: ApiKeyIn, request: Request, db: AsyncSession = Depends(lambda: SessionLocal())):
        user = await current_user_from_request(request, db)
        out = await svc_add_api_key(db, user, payload)
        await generate_html_report()
        return out

    @app.get("/api-keys", response_model=List[ApiKeyOut])
    async def list_api_keys(request: Request, db: AsyncSession = Depends(lambda: SessionLocal())):
        user = await current_user_from_request(request, db)
        return await svc_list_api_keys(db, user)

    @app.get("/me", response_model=MeOut)
    async def me(request: Request, db: AsyncSession = Depends(lambda: SessionLocal())):
        user = await current_user_from_request(request, db)
        return await svc_me(db, user)

    class FillIn(BaseModel):
        triangle: str
        notional_usd: float
        net_usd: float

    @app.post("/engine/submit_fill")
    async def submit_fill(payload: FillIn, request: Request, db: AsyncSession = Depends(lambda: SessionLocal())):
        user = await current_user_from_token(db, request.query_params.get("token") or request.headers.get("Authorization", "").replace("Bearer ", ""))
        out = await svc_submit_fill(db, user, payload.triangle, payload.notional_usd, payload.net_usd)
        await generate_html_report()
        return out

    @app.get("/", response_class=HTMLResponse)
    async def home() -> Any:
        html = f"""
        <!doctype html><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
        <title>CryptoPirate Platform</title>
        <style>body{{font-family:system-ui;background:#0b1020;color:#e6eefc;margin:0}}header{{padding:16px 20px;border-bottom:1px solid #1f2a44}}.wrap{{padding:20px}}input,button{{padding:10px;border-radius:10px;border:1px solid #223;background:#0f1630;color:#e6eefc}}</style>
        <header><h1>🏴‍☠️ CryptoPirate Platform</h1></header>
        <div class=wrap>
          <p>This server is <b>online</b>. REST endpoints available. A local HTML report is also written at <code>{REPORT_PATH}</code> and auto‑refreshes when opened in a browser.</p>
        </div>
        """
        return HTMLResponse(html)

# --- Simulated engine (shared) ---
async def simulated_engine_loop():
    await asyncio.sleep(0.5)
    print("⚙️  Simulated engine started. Wire your real engine to svc_submit_fill or the HTTP endpoint.")
    while True:
        async with SessionLocal() as db:
            users = (await db.execute(select(User))).scalars().all()
            for u in users:
                # Only simulate if the user has at least one API key linked
                has_key = (await db.execute(select(ApiCredential).where(ApiCredential.user_id == u.id))).scalars().first()
                if not has_key:
                    continue
                _ = await svc_submit_fill(db, u, "BTC-USD -> ETH-BTC -> ETH-USD", 50.0, 0.85)
        await generate_html_report()
        await asyncio.sleep(10)

# --- Headless demo (no web) ---
async def headless_demo() -> None:
    await db_init()
    await generate_html_report()
    print("\n🔧 Running headless demo (no ssl / no FastAPI). Core logic still works.")
    print(f"📄 Open the local report: {REPORT_PATH}\n")
    async with SessionLocal() as db:
        # 1) sign up
        token = await svc_signup(db, "demo@example.com", "demo")
        # 2) login
        token2 = await svc_login(db, "demo@example.com", "demo")
        # 3) get user
        user = await svc_user_from_token(db, token2)
        # 4) add API key
        _ = await svc_add_api_key(db, user, ApiKeyIn(exchange="coinbase", name="primary", key="K", secret="S", passphrase="P"))
        # 5) submit a trade fill
        _ = await svc_submit_fill(db, user, "BTC-USD -> ETH-BTC -> ETH-USD", 100.0, 2.0)
    await generate_html_report()
    if ENGINE_RUN:
        print("Starting simulated engine in background (Ctrl+C to exit)…\n")
        try:
            await simulated_engine_loop()
        except KeyboardInterrupt:
            pass

# --- Tests ---
import unittest
import tempfile

class TestPlatform(unittest.TestCase):
    def test_encrypt_roundtrip(self):
        data = {"a": 1, "b": "x"}
        s = fernet.encrypt(__import__("json").dumps(data).encode())
        back = __import__("json").loads(fernet.decrypt(s).decode())
        self.assertEqual(back, data)

    def test_signup_login_and_trade(self):
        async def _run():
            await db_init()
            async with SessionLocal() as db:
                tok = await svc_signup(db, "t1@example.com", "pw")
                self.assertTrue(isinstance(tok, str) and len(tok) > 10)
                tok2 = await svc_login(db, "t1@example.com", "pw")
                self.assertTrue(isinstance(tok2, str))
                user = await svc_user_from_token(db, tok2)
                out = await svc_add_api_key(db, user, ApiKeyIn(exchange="coinbase", name="p", key="k", secret="s", passphrase="p"))
                self.assertTrue(out.id > 0)
                tr = await svc_submit_fill(db, user, "A-USD -> A-B -> B-USD", 100.0, 1.0)
                self.assertAlmostEqual(tr.platform_fee_usd, 0.05, places=6)  # 5% of $1
                me = await svc_me(db, user)
                self.assertAlmostEqual(me.pnl_total_usd, 0.95, places=6)
        asyncio.run(_run())

    def test_report_generation(self):
        async def _run(tmpfile: str):
            global REPORT_PATH
            REPORT_PATH, old = tmpfile, REPORT_PATH
            try:
                await db_init()
                async with SessionLocal() as db:
                    tok = await svc_signup(db, "rep@example.com", "pw")
                    user = await svc_user_from_token(db, tok)
                    _ = await svc_submit_fill(db, user, "X-USD -> X-Y -> Y-USD", 42.0, 0.42)
                path = await generate_html_report(tmpfile)
                self.assertTrue(os.path.exists(path))
                with open(path, "r", encoding="utf-8") as f:
                    html = f.read()
                self.assertIn("CryptoPirate — Local Report".replace(" — ", " - "), html.replace(" — ", " - "))
                self.assertIn("rep@example.com", html)
            finally:
                REPORT_PATH = old
        with tempfile.TemporaryDirectory() as td:
            asyncio.run(_run(os.path.join(td, "report.html")))

# --- CLI ---
import argparse

def parse_cli() -> argparse.Namespace:
    p = argparse.ArgumentParser("CryptoPirate Platform")
    p.add_argument("--serve", action="store_true", help="run FastAPI server if available, else headless demo")
    p.add_argument("--self-test", action="store_true", help="run unit tests and exit")
    p.add_argument("--report-path", type=str, default=REPORT_PATH_DEFAULT, help="where to write the local HTML report")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_cli()
    REPORT_PATH = args.report_path or REPORT_PATH_DEFAULT
    if args.self_test:
        unittest.main(argv=["-v"], exit=False)
    elif args.serve:
        if FASTAPI_OK:
            # Start uvicorn only if FastAPI imported successfully (ssl present)
            import uvicorn  # imported lazily to avoid ssl import chains
            asyncio.run(db_init())
            # also pre‑write report so you can open it directly
            asyncio.run(generate_html_report())
            uvicorn.run("platform:app", host="0.0.0.0", port=8000, reload=False)
        else:
            # Fallback: run a console demo so the script doesn't crash in ssl‑less sandboxes
            asyncio.run(headless_demo())
    else:
        print("Nothing to do. Use --serve (server/headless) or --self-test (unit tests).")
