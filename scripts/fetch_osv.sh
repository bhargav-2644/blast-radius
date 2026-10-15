#!/usr/bin/env sh
# Download the OSV npm advisory dump (public, no login) used by the loader (D-005).
set -e
mkdir -p data/raw
curl -fSL -o data/raw/npm-osv.zip https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
