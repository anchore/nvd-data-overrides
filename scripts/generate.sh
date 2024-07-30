#!/bin/bash -l
set -euxo pipefail

git -C "cve-data-enrichment" pull || git clone --depth 1 https://github.com/anchore/cve-data-enrichment cve-data-enrichment
git -C "national-vulnerability-database" pull || git clone --depth 1 https://github.com/westonsteimel/national-vulnerability-database national-vulnerability-database

python scripts/generate.py