.PHONY: backend frontend test build dev

backend:
	cd backend && uv sync --frozen

frontend:
	cd frontend && npm ci

test:
	cd backend && uv run pytest -q

build:
	cd frontend && npm run build

dev:
	@echo "Run backend and frontend in separate terminals; see README.md"
