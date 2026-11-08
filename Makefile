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

dev:
	@echo "Starting frontend and backend..."
	$(MAKE) --no-print-directory dev-backend & \
	$(MAKE) --no-print-directory dev-frontend

dev-frontend:
	cd frontend && bun run dev

dev-backend:
	cd backend && uv run fastapi dev app/main.py --host 127.0.0.1 --port 8000
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
