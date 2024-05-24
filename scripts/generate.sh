#!/bin/bash -l
git clone --depth 0 https://github.com/anchore/cve-data-enrichment
git clone --depth 0 https://github.com/westonsteimel/national-vulnerability-database

python scripts/generate.py