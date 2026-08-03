# ═══════════════════════════════════════════════════════════
# SentinelX AI – Developer Commands
# ═══════════════════════════════════════════════════════════

.PHONY: help install dev frontend backend test lint docker-up docker-down clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Setup ────────────────────────────────────────────────

install: ## Install all dependencies
	cd frontend && npm install
	cd backend && pip install -r requirements.txt

# ── Development ──────────────────────────────────────────

dev: ## Start both frontend and backend
	$(MAKE) -j2 frontend backend

frontend: ## Start frontend dev server
	cd frontend && npm run dev

backend: ## Start backend dev server
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# ── Testing ──────────────────────────────────────────────

test: ## Run backend tests
	cd backend && pytest

lint: ## Run linters
	cd backend && ruff check .
	cd frontend && npx tsc --noEmit

# ── Docker ───────────────────────────────────────────────

docker-up: ## Start all services with Docker Compose
	docker compose up --build -d

docker-down: ## Stop all Docker services
	docker compose down

# ── Utilities ────────────────────────────────────────────

clean: ## Remove generated files
	find backend -type d -name __pycache__ -exec rm -rf {} +
	rm -rf frontend/dist frontend/node_modules/.cache
	rm -rf backend/.pytest_cache backend/.mypy_cache
