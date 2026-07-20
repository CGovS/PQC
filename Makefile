# PQC — reproducible entry points. Phase 1 needs only Python 3.11+.
.PHONY: help setup test demo demo-ladder clean

PY ?= python3

help:
	@echo "make setup        install dev deps (pytest) in editable mode"
	@echo "make test         run the test suite"
	@echo "make demo         seal + open a vault at the warmup level"
	@echo "make demo-ladder  run the demo across every RSA level"

setup:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

demo:
	$(PY) -m maze.cli demo --level warmup

demo-ladder:
	@for lvl in warmup easy ceiling; do \
		$(PY) -m maze.cli demo --level $$lvl; echo; \
	done

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
