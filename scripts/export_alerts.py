#!/usr/bin/env python3
"""
export_alerts.py — Extrai os alertas de Code Scanning (CodeQL) via API do GitHub
e envia para onde você precisar.

Saídas:
  * alerts.json  — dados completos normalizados (para importar em outro sistema)
  * alerts.csv   — para planilha / BI
  * alerts.html  — relatório legível
  * Webhook      — Slack, Discord, Microsoft Teams ou "generic" (JSON puro p/ qualquer API,
                   ex.: seu sistema de tickets interno)
  * Issues       — opcional, cria uma issue por alerta (sem duplicar)

Sem dependências externas (só stdlib). Variáveis de ambiente:
  GITHUB_TOKEN       token com permissão de leitura de code scanning
                     (no Actions: permissions: security-events: read)
  GITHUB_REPOSITORY  owner/repo (o Actions já define)
  WEBHOOK_URL        opcional — URL do webhook
  GITHUB_API_URL     opcional — padrão https://api.github.com

Exemplos:
  python scripts/export_alerts.py --out-dir report
  python scripts/export_alerts.py --min-severity high --webhook-format slack
  python scripts/export_alerts.py --create-issues --min-severity high
"""
import argparse
import csv
import html
import json
import os
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
COLORS = {"critical": "#b60205", "high": "#d93f0b", "medium": "#fbca04", "low": "#0e8a16", "none": "#cccccc"}


def gh(method, path_or_url, token, body=None):
    url = path_or_url if path_or_url.startswith("http") else f"{API}{path_or_url}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "codeql-export-script",
        **({"Content-Type": "application/json"} if data else {}),
    })
    with urllib.request.urlopen(req, timeout=30) as resp:
        link = resp.headers.get("Link", "")
        payload = resp.read()
        return (json.loads(payload) if payload else None), link


def list_alerts(repo, token, state, ref, tool):
    params = f"per_page=100&state={state}&tool_name={tool}"
    if ref:
        params += f"&ref={ref}"
    url = f"/repos/{repo}/code-scanning/alerts?{params}"
    alerts = []
    while url:
        page, link = gh("GET", url, token)
        alerts.extend(page)
        m = re.search(r'<([^>]+)>;\s*rel="next"', link or "")
        url = m.group(1) if m else None
    return alerts


def normalize(a):
    rule = a.get("rule", {})
    inst = a.get("most_recent_instance", {}) or {}
    loc = inst.get("location", {}) or {}
    level = rule.get("security_severity_level") or "none"
    return {
        "number": a.get("number"),
        "state": a.get("state"),
        "severity": level,
        "rule_id": rule.get("id"),
        "rule_description": rule.get("description"),
        "cwe": ",".join(t for t in rule.get("tags", []) if "cwe" in t.lower()),
        "tool": a.get("tool", {}).get("name"),
        "file": loc.get("path"),
        "line": loc.get("start_line"),
        "message": (inst.get("message", {}) or {}).get("text", "").splitlines()[0] if inst else "",
        "ref": inst.get("ref"),
        "commit_sha": inst.get("commit_sha"),
        "created_at": a.get("created_at"),
        "url": a.get("html_url"),
    }


def write_files(alerts, out_dir, repo):
    os.makedirs(out_dir, exist_ok=True)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    with open(os.path.join(out_dir, "alerts.json"), "w", encoding="utf-8") as fh:
        json.dump({"repository": repo, "generated_at": generated, "total": len(alerts), "alerts": alerts},
                  fh, indent=2, ensure_ascii=False)

    fields = ["number", "severity", "rule_id", "rule_description", "cwe", "file", "line",
              "state", "created_at", "url"]
    with open(os.path.join(out_dir, "alerts.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(alerts)

    counts = {k: sum(1 for a in alerts if a["severity"] == k) for k in ["critical", "high", "medium", "low"]}
    cards = "".join(
        f'<div class="card" style="border-color:{COLORS[k]}"><b>{v}</b><span>{k}</span></div>'
        for k, v in counts.items())
    rows = "".join(
        f'<tr><td><span class="sev" style="background:{COLORS[a["severity"]]}">{a["severity"]}</span></td>'
        f'<td><a href="{html.escape(a["url"] or "")}">#{a["number"]}</a></td>'
        f'<td><code>{html.escape(a["rule_id"] or "")}</code><br><small>{html.escape(a["rule_description"] or "")}</small></td>'
        f'<td><code>{html.escape(a["file"] or "")}:{a["line"]}</code></td>'
        f'<td>{html.escape(a["cwe"])}</td><td>{html.escape((a["created_at"] or "")[:10])}</td></tr>'
        for a in alerts)
    page = f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8">
<title>CodeQL — {html.escape(repo)}</title><style>
body{{font-family:system-ui,sans-serif;margin:2rem;color:#1f2328}}
.cards{{display:flex;gap:1rem;margin:1rem 0}}.card{{border-left:6px solid;padding:.6rem 1rem;background:#f6f8fa;min-width:110px}}
.card b{{font-size:1.8rem;display:block}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #d0d7de;padding:.45rem;text-align:left;vertical-align:top}}
.sev{{color:#fff;padding:.1rem .5rem;border-radius:4px;font-size:.8rem;text-transform:uppercase}}
</style></head><body><h1>Relatório CodeQL — {html.escape(repo)}</h1>
<p>Gerado em {generated} · {len(alerts)} alerta(s)</p><div class="cards">{cards}</div>
<table><tr><th>Severidade</th><th>Alerta</th><th>Regra</th><th>Local</th><th>CWE</th><th>Criado</th></tr>{rows}</table>
</body></html>"""
    with open(os.path.join(out_dir, "alerts.html"), "w", encoding="utf-8") as fh:
        fh.write(page)
    return counts


def build_webhook_payload(fmt, alerts, counts, repo, run_url):
    title = f"CodeQL · {repo}: {counts['critical']} critical, {counts['high']} high, " \
            f"{counts['medium']} medium, {counts['low']} low"
    top = alerts[:10]
    lines = [f"• [{a['severity'].upper()}] {a['rule_id']} — {a['file']}:{a['line']} ({a['url']})" for a in top]
    if len(alerts) > len(top):
        lines.append(f"… e mais {len(alerts) - len(top)} alerta(s)")
    text = "\n".join(lines) or "Nenhum alerta aberto 🎉"
    if fmt == "slack":
        return {"text": f"*{title}*\n{text}\n<{run_url}|Ver execução>"}
    if fmt == "discord":
        return {"content": f"**{title}**\n{text}\n{run_url}"[:1990]}
    if fmt == "teams":
        return {"type": "message", "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {"type": "AdaptiveCard", "version": "1.4", "body": [
                {"type": "TextBlock", "text": title, "weight": "Bolder", "wrap": True},
                {"type": "TextBlock", "text": text.replace("\n", "\n\n"), "wrap": True}],
                "actions": [{"type": "Action.OpenUrl", "title": "Ver execução", "url": run_url}]}}]}
    # generic: JSON estruturado — ideal para integrar em sistema de tickets/SIEM
    return {"source": "github-codeql", "repository": repo, "run_url": run_url,
            "summary": counts, "alerts": alerts}


def post_webhook(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "codeql-export-script"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status


def create_issues(alerts, repo, token):
    """Cria uma issue por alerta, sem duplicar (procura o marcador no título)."""
    existing, url = set(), f"/repos/{repo}/issues?state=all&labels=codeql&per_page=100"
    while url:
        page, link = gh("GET", url, token)
        for i in page:
            m = re.search(r"\[CodeQL #(\d+)\]", i.get("title", ""))
            if m:
                existing.add(int(m.group(1)))
        m = re.search(r'<([^>]+)>;\s*rel="next"', link or "")
        url = m.group(1) if m else None
    created = 0
    for a in alerts:
        if a["number"] in existing:
            continue
        body = (f"**Severidade:** {a['severity']}\n**Regra:** `{a['rule_id']}` — {a['rule_description']}\n"
                f"**CWE:** {a['cwe']}\n**Local:** `{a['file']}:{a['line']}`\n\n> {a['message']}\n\n"
                f"Alerta: {a['url']}\n\n_Issue criada automaticamente pelo pipeline de CodeQL._")
        gh("POST", f"/repos/{repo}/issues", token, {
            "title": f"[CodeQL #{a['number']}] {a['severity'].upper()}: {a['rule_description']}",
            "body": body, "labels": ["codeql", "security", f"severity:{a['severity']}"]})
        created += 1
    return created


def main():
    ap = argparse.ArgumentParser(description="Exporta alertas de Code Scanning do GitHub")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    ap.add_argument("--state", default="open", choices=["open", "closed", "dismissed", "fixed"])
    ap.add_argument("--ref", help="ex.: refs/heads/main (padrão: branch default)")
    ap.add_argument("--tool", default="CodeQL")
    ap.add_argument("--min-severity", default="low", choices=["low", "medium", "high", "critical"])
    ap.add_argument("--out-dir", default="codeql-report")
    ap.add_argument("--webhook-url", default=os.environ.get("WEBHOOK_URL"))
    ap.add_argument("--webhook-format", default=os.environ.get("WEBHOOK_FORMAT", "generic"),
                    choices=["slack", "discord", "teams", "generic"])
    ap.add_argument("--create-issues", action="store_true")
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token or not args.repo:
        print("::error::Defina GITHUB_TOKEN e GITHUB_REPOSITORY (ou --repo owner/repo)")
        return 2

    try:
        raw = list_alerts(args.repo, token, args.state, args.ref, args.tool)
    except urllib.error.HTTPError as e:
        print(f"::error::Falha ao consultar a API ({e.code}): {e.read().decode()[:300]}")
        print("Dica: o repositório precisa ser público (GitHub Free) e o token precisa de "
              "security-events: read / 'Code scanning alerts: Read'.")
        return 1

    alerts = [normalize(a) for a in raw]
    alerts = [a for a in alerts if RANK[a["severity"]] >= RANK[args.min_severity]]
    alerts.sort(key=lambda a: (-RANK[a["severity"]], a["file"] or "", a["line"] or 0))

    counts = write_files(alerts, args.out_dir, args.repo)
    print(f"{len(alerts)} alerta(s) exportado(s) para {args.out_dir}/ -> {counts}")

    run_url = (f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{args.repo}"
               + (f"/actions/runs/{os.environ['GITHUB_RUN_ID']}" if os.environ.get("GITHUB_RUN_ID")
                  else "/security/code-scanning"))

    if args.webhook_url:
        payload = build_webhook_payload(args.webhook_format, alerts, counts, args.repo, run_url)
        try:
            print(f"Webhook ({args.webhook_format}) -> HTTP {post_webhook(args.webhook_url, payload)}")
        except urllib.error.URLError as e:
            print(f"::warning::Falha ao enviar webhook: {e}")

    if args.create_issues:
        print(f"Issues criadas: {create_issues(alerts, args.repo, token)}")

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"## 📤 Exportação CodeQL\n\n{len(alerts)} alerta(s) abertos "
                     f"(>= {args.min_severity}): {counts}\n\nArquivos: alerts.json, alerts.csv, alerts.html\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
