#!/bin/bash -l
set -euxo pipefail

commit=$(git -C cve-data-enrichment rev-parse HEAD)
git add .
git diff-index --quiet HEAD || git commit --message "chore: generate overrides as of https://github.com/anchore/cve-data-enrichment/commit/${commit}"
