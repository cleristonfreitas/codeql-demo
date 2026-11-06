#!/usr/bin/env python3
"""
sarif_gate.py — Quality gate de segurança a partir dos SARIF do CodeQL.

Lê todos os .sarif de um diretório, classifica cada achado pela
"security-severity" (mesma escala que o GitHub usa) e sai com código 1
se houver achado igual ou acima do limite (--fail-on).

Escala do GitHub (security-severity -> nível):
    >= 9.0  critical
    >= 7.0  high
    >= 4.0  medium
    >  0.0  low

Sem dependências externas. Uso:
    python scripts/sarif_gate.py --sarif-dir sarif-results --fail-on high \
        --json-out findings.json --summary "$GITHUB_STEP_SUMMARY"
"""
import argparse
import glob
import json
import os
import sys

LEVELS = ["none", "low", "medium", "high", "critical"]
RANK = {name: i for i, name in enumerate(LEVELS)}
ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "none": "⬜"}


def score_to_level(score):
    if score is None:
        return "none"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def collect_rules(run):
    """Mapeia rule id -> metadados. O CodeQL coloca regras no driver e nas extensions (packs)."""
    rules = {}
    tool = run.get("tool", {})
    components = [tool.get("driver", {})] + tool.get("extensions", [])
    for comp in components:
        for rule in comp.get("rules", []) or []:
            rules[rule.get("id")] = rule
    return rules


def parse_sarif(path):
    findings = []
    with open(path, encoding="utf-8") as fh:
        sarif = json.load(fh)
    for run in sarif.get("runs", []):
        rules = collect_rules(run)
        lang = run.get("properties", {}).get("semmle.sourceLanguage") or os.path.basename(path).split(".")[0]
        for res in run.get("results", []):
            # ignora achados suprimidos (ex.: dismiss/inline suppression)
            if res.get("suppressions"):
                continue
            rule_id = res.get("ruleId") or res.get("rule", {}).get("id")
            rule = rules.get(rule_id, {})
            props = rule.get("properties", {})
            raw = props.get("security-severity")
            score = float(raw) if raw not in (None, "") else None
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            findings.append({
                "rule_id": rule_id,
                "rule_name": rule.get("shortDescription", {}).get("text") or rule.get("name") or rule_id,
                "level": score_to_level(score),
                "security_severity": score,
                "cwe": [t for t in props.get("tags", []) if "cwe" in t.lower()],
                "file": loc.get("artifactLocation", {}).get("uri"),
                "line": loc.get("region", {}).get("startLine"),
                "message": res.get("message", {}).get("text", "").splitlines()[0][:200],
                "language": lang,
            })
    return findings


def write_summary(path, findings, threshold, blocked):
    counts = {lvl: sum(1 for f in findings if f["level"] == lvl) for lvl in LEVELS}
    lines = ["## 🔐 CodeQL — Security Gate", ""]
    lines.append(f"**Limite de bloqueio:** `{threshold}` ou maior  ")
    lines.append(f"**Resultado:** {'❌ BLOQUEADO' if blocked else '✅ APROVADO'}")
    lines.append("")
    lines.append("| Critical | High | Medium | Low | Sem severidade |")
    lines.append("|---|---|---|---|---|")
    lines.append(f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} | {counts['none']} |")
    lines.append("")
    if findings:
        lines.append("| Sev. | Score | Regra | Arquivo | Linha |")
        lines.append("|---|---|---|---|---|")
        for f in findings:
            score = "-" if f["security_severity"] is None else f'{f["security_severity"]:.1f}'
            lines.append(f'| {ICON[f["level"]]} {f["level"]} | {score} | `{f["rule_id"]}` | `{f["file"]}` | {f["line"]} |')
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main():
    ap = argparse.ArgumentParser(description="Bloqueia o pipeline com base na severidade dos achados CodeQL")
    ap.add_argument("--sarif-dir", default="sarif-results")
    ap.add_argument("--fail-on", default="high", choices=["critical", "high", "medium", "low"],
                    help="severidade mínima que bloqueia (padrão: high => bloqueia high e critical)")
    ap.add_argument("--json-out", help="grava os achados normalizados em JSON")
    ap.add_argument("--summary", help="arquivo de summary (no Actions use $GITHUB_STEP_SUMMARY)")
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.sarif_dir, "**", "*.sarif"), recursive=True))
    if not files:
        print(f"::error::Nenhum SARIF encontrado em {args.sarif_dir}")
        return 2

    findings = []
    for f in files:
        findings.extend(parse_sarif(f))
    findings.sort(key=lambda f: (-(f["security_severity"] or 0), f["file"] or "", f["line"] or 0))

    blocking = [f for f in findings if RANK[f["level"]] >= RANK[args.fail_on]]
    blocked = bool(blocking)

    print(f"SARIF analisados: {', '.join(files)}")
    print(f"Total de achados: {len(findings)} | bloqueantes (>= {args.fail_on}): {len(blocking)}\n")
    for f in findings:
        score = "  - " if f["security_severity"] is None else f'{f["security_severity"]:4.1f}'
        print(f'[{f["level"].upper():8}] {score}  {f["rule_id"]:45} {f["file"]}:{f["line"]}')
        # Anotações aparecem na aba "Files changed" do PR e no resumo do job
        cmd = "error" if f in blocking else "warning"
        print(f'::{cmd} file={f["file"]},line={f["line"]},title=CodeQL {f["level"]} ({f["rule_id"]})::{f["message"]}')

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"threshold": args.fail_on, "blocked": blocked, "findings": findings}, fh,
                      indent=2, ensure_ascii=False)
    if args.summary:
        write_summary(args.summary, findings, args.fail_on, blocked)

    if blocked:
        print(f"\n❌ Pipeline bloqueado: {len(blocking)} achado(s) com severidade >= {args.fail_on}.")
        return 1
    print("\n✅ Nenhum achado bloqueante.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
