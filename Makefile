# AI Multi-Service Security & Automation Platform
.PHONY: help setup start stop test build clean

help: ## Show this help
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

setup: ## Setup development environment
	@echo "🔧 Setting up development environment..."
	@python3 generate_boilerplate.py
	@echo "✅ Setup complete!"

start: ## Start all services
	@echo "🚀 Starting all services..."
	@cd infrastructure/docker && docker-compose up -d
	@echo "✅ All services started!"
	@echo "   API Gateway: http://localhost:8000"
	@echo "   AI Hub: http://localhost:8001"
	@echo "   Scanner: http://localhost:8002"
	@echo "   Labyrinth: http://localhost:8003"
	@echo "   n8n: http://localhost:5678"
	@echo "   Frontend: http://localhost:3000"

stop: ## Stop all services
	@echo "🛑 Stopping all services..."
	@cd infrastructure/docker && docker-compose down
	@echo "✅ All services stopped!"

test: ## Run all tests
	@echo "🧪 Running tests..."
	@cd services/api-gateway && pytest
	@cd services/ai-hub && pytest
	@cd services/scanner-go && go test ./...
	@cd services/labyrinth-rust && cargo test
	@echo "✅ All tests passed!"

build: ## Build all services
	@echo "🔨 Building all services..."
	@cd infrastructure/docker && docker-compose build
	@echo "✅ All services built!"

clean: ## Clean up
	@echo "🧹 Cleaning up..."
	@cd infrastructure/docker && docker-compose down -v
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name "node_modules" -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Cleanup complete!"

logs: ## Show logs
	@cd infrastructure/docker && docker-compose logs -f

status: ## Show service status
	@cd infrastructure/docker && docker-compose ps
