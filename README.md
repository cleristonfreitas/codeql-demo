# codeql-demo — CodeQL grátis + Security Gate + exportação de alertas

> ⚠️ `app/app.py` é **propositalmente vulnerável**. Não faça deploy.

| O quê | Onde |
|---|---|
| App vulnerável (10 falhas, 4 critical / 6 high) | `app/app.py` |
| Versão corrigida (para provar que o gate libera) | `docs/app_secure.py` |
| Pipeline CodeQL + bloqueio CRITICAL/HIGH | `.github/workflows/codeql.yml` |
| Configuração do CodeQL (security-extended) | `.github/codeql/codeql-config.yml` |
| Gate a partir do SARIF | `scripts/sarif_gate.py` |
| Exportação (JSON/CSV/HTML, webhook, issues) | `scripts/export_alerts.py` + `.github/workflows/codeql-export.yml` |
| Ruleset que bloqueia merge na main | `.github/rulesets/protect-main.json` + `scripts/setup_repo.sh` |
| Scan local | `scripts/local_scan.sh` |

## Início rápido

```bash
gh repo create codeql-demo --public --source=. --push   # PÚBLICO: obrigatório no GitHub Free
./scripts/setup_repo.sh SEU_USUARIO/codeql-demo
```

Depois: **Actions** → veja o job `Analyze (python)` falhar com 10 achados bloqueantes
e **Security → Code scanning** com os alertas.

## Variáveis

| Nome | Tipo | Padrão | Função |
|---|---|---|---|
| `CODEQL_FAIL_ON` | variable | `high` | `critical` / `high` / `medium` / `low` |
| `CODEQL_WEBHOOK_URL` | secret | — | Slack, Discord, Teams ou API própria |
| `CODEQL_WEBHOOK_FORMAT` | variable | `generic` | `slack` / `discord` / `teams` / `generic` |
| `CODEQL_CREATE_ISSUES` | variable | `false` | cria issue para cada high/critical |

## Exportar na sua máquina

```bash
export GITHUB_TOKEN=$(gh auth token) GITHUB_REPOSITORY=SEU_USUARIO/codeql-demo
python3 scripts/export_alerts.py --out-dir report
```
