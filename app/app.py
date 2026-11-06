"""
VulnShop - aplicação Flask PROPOSITALMENTE VULNERÁVEL.

⚠️  NÃO FAÇA DEPLOY DESTE CÓDIGO. Ele existe apenas para demonstrar o
CodeQL encontrando vulnerabilidades e o pipeline bloqueando o merge.

Cada rota tem um comentário com a vulnerabilidade, o ID da regra CodeQL
que deve disparar e a severidade esperada (security-severity / CVSS).
"""
import base64
import hashlib
import logging
import os
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, make_response, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("vulnshop")

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnshop.db")
FILES_DIR = os.path.join(os.path.dirname(__file__), "files")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
    )
    return conn


# 1) SQL Injection — py/sql-injection — HIGH (8.8)
@app.route("/users")
def search_user():
    username = request.args.get("username", "")
    conn = get_db()
    query = f"SELECT id, username FROM users WHERE username = '{username}'"
    rows = conn.execute(query).fetchall()
    return {"users": rows}


# 2) Command Injection — py/command-line-injection — CRITICAL (9.8)
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return {"output": result.stdout}


# 3) Path Traversal — py/path-injection — HIGH (7.5)
@app.route("/download")
def download():
    filename = request.args.get("file", "readme.txt")
    path = os.path.join(FILES_DIR, filename)
    with open(path, "r") as fh:
        return fh.read()


# 4) Desserialização insegura — py/unsafe-deserialization — CRITICAL (9.8)
@app.route("/cart/restore", methods=["POST"])
def restore_cart():
    raw = base64.b64decode(request.form.get("cart", ""))
    cart = pickle.loads(raw)
    return {"items": len(cart)}


# 5) SSRF — py/full-ssrf — CRITICAL (9.1)
#@app.route("/preview")
#def preview():
#    url = request.args.get("url", "")
#    resp = requests.get(url, timeout=5)
 #   return {"status": resp.status_code, "length": len(resp.content)}
#

# 6) Code Injection — py/code-injection — CRITICAL (9.3)
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    return {"result": eval(expr)}


# 7) XSS refletido — py/reflective-xss — HIGH (7.8)
@app.route("/hello")
def hello():
    name = request.args.get("name", "visitante")
    return make_response(f"<h1>Olá, {name}!</h1>")


# 8) Hash fraco para senha — py/weak-sensitive-data-hashing — HIGH (7.5)
# 9) Log de dado sensível em texto claro — py/clear-text-logging-sensitive-data — HIGH (7.5)
#    (bônus: py/log-injection — MEDIUM (6.1) — aparece no relatório, mas NÃO bloqueia)
@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    log.info("Novo cadastro: user=%s password=%s", username, password)
    hashed = hashlib.md5(password.encode()).hexdigest()
    conn = get_db()
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
    conn.commit()
    return {"ok": True}


if __name__ == "__main__":
    # 10) Flask em modo debug — py/flask-debug — HIGH (7.5)
    app.run(host="0.0.0.0", port=5000, debug=True)
