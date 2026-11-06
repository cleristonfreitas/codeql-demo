"""
Versão CORRIGIDA do VulnShop — use para provar que o gate libera o pipeline.

Copie este arquivo por cima de app/app.py num branch, abra o PR e veja o
"CodeQL Security Gate" passar e os alertas serem fechados como "Fixed".
"""
import json
import logging
import os
import re
import sqlite3
import subprocess
from urllib.parse import urlparse

import requests
from flask import Flask, abort, request, send_from_directory
from markupsafe import escape as html_escape
from werkzeug.security import generate_password_hash

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("vulnshop")

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnshop.db")
FILES_DIR = os.path.join(os.path.dirname(__file__), "files")
ALLOWED_PREVIEW_HOSTS = {"example.com", "www.example.com"}
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    return conn


# 1) SQLi corrigido: query parametrizada
@app.route("/users")
def search_user():
    username = request.args.get("username", "")
    rows = get_db().execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchall()
    return {"users": rows}


# 2) Command injection corrigido: sem shell, argumento validado
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    if not HOST_RE.match(host):
        abort(400)
    result = subprocess.run(["ping", "-c", "1", "--", host], capture_output=True, text=True)
    return {"output": result.stdout}


# 3) Path traversal corrigido: send_from_directory valida o caminho
@app.route("/download")
def download():
    return send_from_directory(FILES_DIR, request.args.get("file", "readme.txt"))


# 4) Desserialização corrigida: JSON em vez de pickle
@app.route("/cart/restore", methods=["POST"])
def restore_cart():
    cart = json.loads(request.form.get("cart", "[]"))
    return {"items": len(cart)}


# 5) SSRF corrigido: allowlist de host fixa
@app.route("/preview")
def preview():
    parsed = urlparse(request.args.get("url", ""))
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_PREVIEW_HOSTS:
        abort(400)
    host = next(h for h in ALLOWED_PREVIEW_HOSTS if h == parsed.hostname)
    resp = requests.get(f"https://{host}/", timeout=5)
    return {"status": resp.status_code, "length": len(resp.content)}


# 6) Code injection corrigido: sem eval, só soma de inteiros
@app.route("/calc")
def calc():
    parts = request.args.get("expr", "1+1").split("+")
    if not all(p.strip().isdigit() for p in parts):
        abort(400)
    return {"result": sum(int(p) for p in parts)}


# 7) XSS corrigido: escape da saída
@app.route("/hello")
def hello():
    return f"<h1>Olá, {html_escape(request.args.get('name', 'visitante'))}!</h1>"


# 8/9) Hash forte (PBKDF2/scrypt) e sem senha no log
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    log.info("Novo cadastro: user=%s", username)
    conn = get_db()
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                 (username, generate_password_hash(password)))
    conn.commit()
    return {"ok": True}


if __name__ == "__main__":
    # 10) debug controlado por variável de ambiente, nunca fixo em True
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
