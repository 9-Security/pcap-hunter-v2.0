.PHONY: install test lint format run clean fix-permissions

install:
	pip install -r requirements.txt

test:
	PYTHONPATH=. pytest tests/ -v --cov=app

lint:
	ruff check .

format:
	ruff format .

run:
	streamlit run app/main.py

clean:
	rm -rf .pytest_cache .coverage htmlcov
	find . -type d -name "__pycache__" -exec rm -rf {} +

fix-permissions:
	@echo "Granting capture permissions for macOS (a system prompt may appear)..."
	@osascript -e 'do shell script "chown $(USER) /dev/bpf*" with administrator privileges'
	@ls -l /dev/bpf*
