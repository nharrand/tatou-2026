.DEFAULT_GOAL := help

PYTHON := .venv/bin/python

.PHONY: help setup test lint coverage coverage-report coverage-html report report-francesco
help:
	@printf '%s\n' \
	  'make help              List available commands (default)' \
	  'make setup             Install Python 3.12 development and analysis tools' \
	  'make test              Run the complete test suite' \
	  'make lint              Run Ruff checks' \
	  'make coverage          Run the complete suite and collect line/branch coverage' \
	  'make coverage-report   Print the saved coverage summary and missing lines' \
	  'make coverage-html     Generate server/htmlcov/index.html from saved coverage' \
	  'make report            Build report/report.pdf' \
	  'make report-francesco  Build the individual mutation-testing report' \
	  'make mutation          Start a fresh campaign for all modules (asks for confirmation)' \
	  'make mutation-backend  Start a fresh backend campaign' \
	  'make mutation-francesco / mutation-davide / mutation-khaled / mutation-common' \
	  'make mutation-pause    Pause the active campaign safely' \
	  'make mutation-resume   Resume the recorded campaign' \
	  'make mutation-results  Print saved mutation results' \
	  'make mutation-browse   Browse saved mutants interactively'

setup:
	python3.12 -m venv server/.venv
	cd server && $(PYTHON) -m pip install -r requirements.txt -e ".[dev]"

test:
	cd server && SECRET_KEY="$$($(PYTHON) -c 'import secrets; print(secrets.token_hex(32))')" $(PYTHON) -m pytest

lint:
	cd server && $(PYTHON) -m ruff check .

coverage:
	cd server && SECRET_KEY="$$($(PYTHON) -c 'import secrets; print(secrets.token_hex(32))')" $(PYTHON) -m pytest -ra --cov=src --cov-branch --cov-report=

coverage-report:
	cd server && $(PYTHON) -m coverage report -m

coverage-html:
	cd server && $(PYTHON) -m coverage html

report:
	$(MAKE) -C report all

report-francesco:
	$(MAKE) -C artifacts/francesco all

# Campaign lifecycle remains in the scripts; Make supplies the public commands.
.PHONY: mutation mutation-backend mutation-francesco mutation-davide mutation-khaled mutation-common
.PHONY: mutation-pause mutation-resume mutation-results mutation-browse
mutation:
	./scripts/run-mutation.sh all

mutation-backend mutation-francesco mutation-davide mutation-khaled mutation-common mutation-pause mutation-resume:
	./scripts/run-mutation.sh $(patsubst mutation-%,%,$@)

mutation-results:
	cd server && .venv/bin/mutmut results

mutation-browse:
	cd server && .venv/bin/mutmut browse

.PHONY: report-watch
report-watch:
	$(MAKE) -C report watch
