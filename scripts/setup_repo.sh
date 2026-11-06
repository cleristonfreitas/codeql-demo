#!/usr/bin/env bash
# Configura o repositório via GitHub CLI:
#   - garante que é público (requisito do GitHub Free para code scanning)
#   - aplica o ruleset que bloqueia merge na main
#   - define variáveis/segredos opcionais
# Uso: ./scripts/setup_repo.sh owner/repo
set -euo pipefail
REPO="${1:?uso: $0 owner/repo}"

echo ">> Visibilidade:"
gh repo view "$REPO" --json visibility -q .visibility

echo ">> Habilitando Dependabot alerts e security updates (gratuitos)"
gh api -X PUT "repos/$REPO/vulnerability-alerts" >/dev/null || true
gh api -X PUT "repos/$REPO/automated-security-fixes" >/dev/null || true

echo ">> Aplicando ruleset protect-main"
gh api -X POST "repos/$REPO/rulesets" --input .github/rulesets/protect-main.json >/dev/null \
  && echo "   ruleset criado" || echo "   (ruleset já existe? veja Settings > Rules > Rulesets)"

echo ">> Variáveis do pipeline"
gh variable set CODEQL_FAIL_ON --body "high" --repo "$REPO"
gh variable set CODEQL_WEBHOOK_FORMAT --body "${WEBHOOK_FORMAT:-generic}" --repo "$REPO"
gh variable set CODEQL_CREATE_ISSUES --body "${CREATE_ISSUES:-false}" --repo "$REPO"

if [[ -n "${WEBHOOK_URL:-}" ]]; then
  gh secret set CODEQL_WEBHOOK_URL --body "$WEBHOOK_URL" --repo "$REPO"
  echo "   segredo CODEQL_WEBHOOK_URL definido"
fi
echo "Pronto."
