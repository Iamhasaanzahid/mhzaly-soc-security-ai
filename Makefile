.PHONY: help install dev test lint scan run deploy

help:           ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

install:        ## Install runtime dependencies
	pip install -r requirements.txt

dev:            ## Install runtime + development dependencies
	pip install -r requirements.txt -r requirements-dev.txt

test:           ## Run the test suite
	python -m pytest

lint:           ## Lint with ruff
	ruff check .

scan:           ## Run one autonomous scan cycle against all active targets
	python -m core.scheduler run-all-once

run:            ## Start the Streamlit dashboard
	streamlit run app.py
