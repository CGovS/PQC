# PQC — reproducible entry points. The maze needs only Python 3.11+;
# the attacker and PQC layer need `make setup` (numpy + kyber-py).
.PHONY: help setup test verify demo demo-ladder report web clean

PY ?= $(if $(wildcard .venv/bin/python),.venv/bin/python,python3)
PORT ?= 8765

help:
	@echo "make setup        install deps (pytest + numpy + kyber-py), editable"
	@echo "make test         run the full test suite"
	@echo "make verify       prove the break + defense are real (end-to-end + JS/Python parity)"
	@echo "make demo         seal + open a vault at the warmup level (stdlib only)"
	@echo "make demo-ladder  run the CLI demo across every RSA level"
	@echo "make report       regenerate the before/after attack data for the web demo"
	@echo "make web          serve the visual demo at http://localhost:$(PORT)/"

setup:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

verify: report
	$(PY) -m attacker.verify

demo:
	$(PY) -m maze.cli demo --level warmup

demo-ladder:
	@for lvl in warmup easy ceiling; do \
		$(PY) -m maze.cli demo --level $$lvl; echo; \
	done

report:
	$(PY) -m attacker.report --level ceiling --seed 3

web:
	@echo "serving visual demo -> http://localhost:$(PORT)/"
	$(PY) -m maze.server --port $(PORT)

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
