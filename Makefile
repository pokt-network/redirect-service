.PHONY: help build run test clean docker-build docker-push docker-run deploy k8s-apply k8s-delete

# Variables
APP_NAME := taiji
VERSION ?= latest
REGISTRY ?= ghcr.io/pokt-network
IMAGE := $(REGISTRY)/$(APP_NAME):$(VERSION)

# Colors for output
COLOR_RESET := \033[0m
COLOR_BOLD := \033[1m
COLOR_GREEN := \033[32m
COLOR_YELLOW := \033[33m

help: ## Show this help message
	@echo "$(COLOR_BOLD)Available targets:$(COLOR_RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_GREEN)%-20s$(COLOR_RESET) %s\n", $$1, $$2}'

build: ## Build the Go binary locally
	@echo "$(COLOR_YELLOW)Building $(APP_NAME)...$(COLOR_RESET)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/$(APP_NAME) main.go
	@echo "$(COLOR_GREEN)✓ Build complete: bin/$(APP_NAME)$(COLOR_RESET)"

run: ## Run the service locally (uses examples/proxies.csv by default)
	@echo "$(COLOR_YELLOW)Running $(APP_NAME) locally...$(COLOR_RESET)"
	PORT=8080 go run main.go

clean: ## Clean build artifacts
	@echo "$(COLOR_YELLOW)Cleaning...$(COLOR_RESET)"
	rm -rf bin/
	rm -f coverage.out
	@echo "$(COLOR_GREEN)✓ Clean complete$(COLOR_RESET)"

docker-build: ## Build Docker image
	@echo "$(COLOR_YELLOW)Building Docker image: $(IMAGE)...$(COLOR_RESET)"
	docker build -t $(IMAGE) .
	@echo "$(COLOR_GREEN)✓ Docker build complete: $(IMAGE)$(COLOR_RESET)"

docker-push: ## Push Docker image to registry
	@echo "$(COLOR_YELLOW)Pushing Docker image: $(IMAGE)...$(COLOR_RESET)"
	docker push $(IMAGE)
	@echo "$(COLOR_GREEN)✓ Docker push complete$(COLOR_RESET)"

docker-run: ## Run Docker container locally
	@echo "$(COLOR_YELLOW)Running Docker container...$(COLOR_RESET)"
	docker run --rm -it \
		-p 8080:8080 \
		-v $(PWD)/examples/proxies.csv:/config/proxies.csv:ro \
		$(IMAGE)

docker-buildx: ## Build multi-platform image (arm64/amd64)
	@echo "$(COLOR_YELLOW)Building multi-platform image: $(IMAGE)...$(COLOR_RESET)"
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		-t $(IMAGE) \
		--push \
		.
	@echo "$(COLOR_GREEN)✓ Multi-platform build complete$(COLOR_RESET)"

fmt: ## Format Go code
	@echo "$(COLOR_YELLOW)Formatting code...$(COLOR_RESET)"
	go fmt ./...
	@echo "$(COLOR_GREEN)✓ Format complete$(COLOR_RESET)"

lint: ## Run linter (requires golangci-lint)
	@echo "$(COLOR_YELLOW)Running linter...$(COLOR_RESET)"
	golangci-lint run
	@echo "$(COLOR_GREEN)✓ Lint complete$(COLOR_RESET)"

deps: ## Download Go dependencies
	@echo "$(COLOR_YELLOW)Downloading dependencies...$(COLOR_RESET)"
	go mod download
	go mod verify
	@echo "$(COLOR_GREEN)✓ Dependencies downloaded$(COLOR_RESET)"

mod-tidy: ## Tidy Go modules
	@echo "$(COLOR_YELLOW)Tidying modules...$(COLOR_RESET)"
	go mod tidy
	@echo "$(COLOR_GREEN)✓ Modules tidied$(COLOR_RESET)"

security-scan: ## Run security scan with trivy
	@echo "$(COLOR_YELLOW)Running security scan...$(COLOR_RESET)"
	trivy image $(IMAGE)
	@echo "$(COLOR_GREEN)✓ Security scan complete$(COLOR_RESET)"
