.DEFAULT_GOAL := help
.PHONY: help install dev dev-frontend dev-backend test lint format build clean

help:
	@printf '%s\n' \
	  'install         Install frontend (Bun) and backend (uv) dependencies' \
	  'dev             Run the Vite and FastAPI development servers together' \
	  'dev-frontend    Run the Vite development server' \
	  'dev-backend     Run the FastAPI development server' \
	  'test            Run the backend pytest suite' \
	  'lint            Run the configured Oxlint checks' \
	  'format          Format frontend source with Oxfmt' \
	  'build           Build the frontend for production' \
	  'clean           Remove frontend build and backend test/cache artifacts'

install:
	cd frontend && bun install
	cd backend && uv sync

# Both servers are needed for the frontend's /api proxy to reach the backend.
dev:
	$(MAKE) --no-print-directory -j2 dev-frontend dev-backend

dev-frontend:
	cd frontend && bun run dev

dev-backend:
	cd backend && uv run fastapi dev app/main.py

test:
	cd backend && uv run pytest

lint:
	cd frontend && bun run lint

format:
	cd frontend && bunx oxfmt --write src

build:
	cd frontend && bun run build

clean:
	rm -rf frontend/dist backend/.pytest_cache
	find backend -type d -name __pycache__ -prune -exec rm -rf {} +
