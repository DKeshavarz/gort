# Project settings
PROJECT_NAME=gort
PKG=./...
MAIN=main.go
BUILD_DIR=.

# Git info
BRANCH=$(shell git rev-parse --abbrev-ref HEAD)

# Docker setting
TEST_TAG=dev
DOCKER_FILE_PATH=.

# Default target
run: ## Run the app
	@clear
	@go run $(MAIN)

all: build ## Build the project (default)

compile: ## Compile (without installing)
	@go build -o $(BUILD_DIR)/$(PROJECT_NAME) $(MAIN)

build: clean compile
	./$(BUILD_DIR)/$(PROJECT_NAME)

test: ## Run tests
	go test $(PKG)

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)/$(PROJECT_NAME)

push: ## Push current branch to origin
	git push origin $(BRANCH)

pull: ## Pull current branch from origin
	git pull origin $(BRANCH)

help: ## Show this help
	@echo "Usage: make [target]"
	@awk 'BEGIN {FS = ":.*##"; printf "\nAvailable targets:\n"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)