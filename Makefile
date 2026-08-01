.PHONY: setup backend frontend test test-backend test-frontend build audit audit-backend audit-frontend check dev

setup: backend frontend

backend:
	cd backend && uv sync --frozen

frontend:
	cd frontend && npm ci

test: test-backend test-frontend

test-backend:
	cd backend && uv run --frozen pytest -q

test-frontend:
	cd frontend && npm test

build:
	cd frontend && npm run build

audit: audit-backend audit-frontend

audit-backend:
	cd backend && uv audit --frozen --preview-features audit-command

audit-frontend:
	cd frontend && npm audit

check: test build audit

dev:
	@echo "Run backend and frontend in separate terminals; see README.md"
