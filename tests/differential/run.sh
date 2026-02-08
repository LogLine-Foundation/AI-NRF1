#!/usr/bin/env bash
set -euo pipefail
python3 -m pip install -r tests/differential/requirements.txt
python3 -c "import sys; print(sys.version)"
pytest -q tests/differential/test_diff_cli_vs_python.py
