#!/usr/bin/env bash
# Roda o CodeQL localmente (mesma suíte do pipeline) e aplica o gate.
# Licença do CodeQL CLI: uso gratuito para pesquisa acadêmica e código open source.
#
# Instalação do CLI (uma vez):
#   curl -L -o codeql.tar.gz https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz
#   tar xzf codeql.tar.gz && export PATH="$PWD/codeql:$PATH"
set -euo pipefail
LANG_="${1:-python}"
FAIL_ON="${2:-high}"
DB=".codeql-db-$LANG_"

codeql database create "$DB" --language="$LANG_" --source-root=. --build-mode=none --overwrite
mkdir -p sarif-results
codeql database analyze "$DB" "codeql/${LANG_}-queries:codeql-suites/${LANG_}-security-extended.qls" \
  --format=sarif-latest --output="sarif-results/${LANG_}.sarif"
python3 scripts/sarif_gate.py --sarif-dir sarif-results --fail-on "$FAIL_ON" | grep -v '^::'
