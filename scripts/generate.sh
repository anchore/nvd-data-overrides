#!/bin/bash -l
set -euxo pipefail

git clone --depth 1 https://github.com/anchore/cve-data-enrichment
git clone --depth 1 https://github.com/westonsteimel/national-vulnerability-database

python scripts/generate.py