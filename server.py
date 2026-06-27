"""
Money Dump - backend (FastAPI + SQLite, single file).

What it does
------------
- Stores each user's expense data on the server (single source of truth).
- Simple username + password login that returns a token which NEVER expires
  (until you log out). Log in once per device and you stay logged in.
- A /api/sync endpoint that merges the device's data with the server's data
  using the same conflict-free, tombstone-based merge the frontend uses.
- Serves the frontend (web/index.html) from the same origin, so there is no
  CORS / mixed-content / Google setup to worry about. One deploy = whole app.

Run locally
-----------
    pip install -r requirements.txt
    uvicorn server:app --reload --port 8000
    # open http://localhost:8000

Environment variables (all optional)
------------------------------------
    MD_DB            path to the sqlite file        (default: moneydump.db)
    MD_MAX_USERS     how many accounts allowed       (default: 2)
    MD_REGISTER_CODE if set, /api/register needs it  (default: none = open
                     registration until MD_MAX_USERS is reached)
    PORT             port to listen on               (default: 8000)
"""

import os
import json
import time
import hmac
import sqlite3
import secrets
import hashlib
import threading
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ---------------------------------------------------------------- config
HERE = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(HERE, "web")
DB_PATH = os.environ.get("MD_DB", os.path.join(HERE, "moneydump.db"))
MAX_USERS = int(os.environ.get("MD_MAX_USERS", "2"))
REGISTER_CODE = os.environ.get("MD_REGISTER_CODE", "").strip()

_lock = threading.Lock()


# ---------------------------------------------------------------- database
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                pwhash   TEXT NOT NULL,
                salt     TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token   TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stores (
                user_id INTEGER PRIMARY KEY,
                data    TEXT NOT NULL,
                updated INTEGER NOT NULL
            );
            """
        )


# ---------------------------------------------------------------- passwords
def hash_pw(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return dk.hex()


def verify_pw(password: str, salt: str, expected: str) -> bool:
    return hmac.compare_digest(hash_pw(password, salt), expected)


# ---------------------------------------------------------------- merge
def merge_stores(a: dict, b: dict) -> dict:
    """Conflict-free merge. Entries are immutable; deletes are tombstones.
    Identical to the frontend's mergeStores()."""
    deleted = list({*(a.get("deleted") or []), *(b.get("deleted") or [])})
    ds = set(deleted)
    seen, out = set(), []
    for e in [*(b.get("entries") or []), *(a.get("entries") or [])]:
        eid = e.get("id")
        if eid in ds or eid in seen:
            continue
        seen.add(eid)
        out.append(e)
    return {"entries": out, "deleted": deleted}


# ---------------------------------------------------------------- auth helper
def user_from_token(token: Optional[str]) -> Optional[sqlite3.Row]:
    if not token:
        return None
    with db() as conn:
        row = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
            "WHERE s.token = ?",
            (token,),
        ).fetchone()
    return row


def require_user(authorization: Optional[str]) -> sqlite3.Row:
    token = None
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    user = user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="not authenticated")
    return user


# ---------------------------------------------------------------- app
app = FastAPI(title="Money Dump")

# Token auth via header (no cookies), so allowing any origin is safe and lets
# you optionally keep the frontend on GitHub Pages pointing at this backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup():
    init_db()


# Also initialise immediately at import, so the tables exist no matter how the
# app is launched (uvicorn, gunicorn, TestClient, etc.).
init_db()


# ---------- models
class AuthIn(BaseModel):
    username: str
    password: str
    code: Optional[str] = None  # registration code, if required


class StoreIn(BaseModel):
    entries: list = []
    deleted: list = []


# ---------- auth endpoints
@app.post("/api/register")
def register(body: AuthIn):
    username = body.username.strip().lower()
    if not username or not body.password:
        raise HTTPException(400, "username and password required")
    if len(body.password) < 4:
        raise HTTPException(400, "password too short")
    if REGISTER_CODE and (body.code or "").strip() != REGISTER_CODE:
        raise HTTPException(403, "invalid registration code")

    with _lock, db() as conn:
        count = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        if count >= MAX_USERS:
            raise HTTPException(403, "registration is closed (max users reached)")
        if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise HTTPException(409, "username already taken")
        salt = secrets.token_hex(16)
        conn.execute(
            "INSERT INTO users (username, pwhash, salt) VALUES (?,?,?)",
            (username, hash_pw(body.password, salt), salt),
        )
        uid = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO sessions (token, user_id, created) VALUES (?,?,?)",
            (token, uid, int(time.time())),
        )
    return {"token": token, "username": username}


@app.post("/api/login")
def login(body: AuthIn):
    username = body.username.strip().lower()
    with db() as conn:
        u = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not u or not verify_pw(body.password, u["salt"], u["pwhash"]):
            raise HTTPException(401, "wrong username or password")
        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO sessions (token, user_id, created) VALUES (?,?,?)",
            (token, u["id"], int(time.time())),
        )
    return {"token": token, "username": username}


@app.get("/api/me")
def me(authorization: Optional[str] = Header(None)):
    user = require_user(authorization)
    return {"username": user["username"]}


@app.post("/api/logout")
def logout(authorization: Optional[str] = Header(None)):
    token = authorization[7:].strip() if authorization and authorization.lower().startswith("bearer ") else None
    if token:
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    return {"ok": True}


# ---------- data endpoints
def load_store(uid: int) -> dict:
    with db() as conn:
        row = conn.execute("SELECT data FROM stores WHERE user_id=?", (uid,)).fetchone()
    if not row:
        return {"entries": [], "deleted": []}
    try:
        return json.loads(row["data"])
    except Exception:
        return {"entries": [], "deleted": []}


def save_store(uid: int, store: dict):
    with db() as conn:
        conn.execute(
            "INSERT INTO stores (user_id, data, updated) VALUES (?,?,?) "
            "ON CONFLICT(user_id) DO UPDATE SET data=excluded.data, updated=excluded.updated",
            (uid, json.dumps(store), int(time.time())),
        )


@app.get("/api/data")
def get_data(authorization: Optional[str] = Header(None)):
    user = require_user(authorization)
    return load_store(user["id"])


@app.post("/api/sync")
def sync(body: StoreIn, authorization: Optional[str] = Header(None)):
    user = require_user(authorization)
    with _lock:
        remote = load_store(user["id"])
        merged = merge_stores({"entries": body.entries, "deleted": body.deleted}, remote)
        save_store(user["id"], merged)
    return merged


# ---------------------------------------------------------------- static site
# Serve the frontend from the same origin. Everything below the API routes.
@app.get("/", response_class=HTMLResponse)
def index():
    path = os.path.join(WEB_DIR, "index.html")
    if os.path.exists(path):
        return FileResponse(path)
    return HTMLResponse("<h1>Money Dump backend is running.</h1>"
                        "<p>Place index.html in the ./web folder.</p>")


@app.get("/health")
def health():
    return {"ok": True}


if os.path.isdir(WEB_DIR):
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="static")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("server:app", host="0.0.0.0", port=int(os.environ.get("PORT", "8000")))
