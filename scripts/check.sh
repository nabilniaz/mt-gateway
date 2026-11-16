#!/bin/sh
# Local quality gate: the same steps CI runs. Usage: ./scripts/check.sh [pytest args]
set -e
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest "$@"
