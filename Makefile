# Makefile for Golang projects

# Variables
BINARY_NAME = ssl-watch
SOURCE_DIR = ./
BUILD_DIR = ./bin
GO_FILES = $(wildcard $(SOURCE_DIR)/*.go)
BIN_FILE = $(BUILD_DIR)/$(BINARY_NAME)

# Containerized toolchain — Go is not required locally; these run in Docker.
GO_IMAGE ?= golang:1.23
LINT_IMAGE ?= golangci/golangci-lint:v2.12.2
DOCKER_RUN = docker run --rm -v "$(CURDIR)":/app -w /app

# Default target
.PHONY: all format test build clean test-docker build-docker lint-docker
all: format test build

# Format the Go files
format:
	@echo "Formatting Go files..."
	@go fmt ./... || { echo "Formatting failed"; exit 1; }

# Run the project tests
test:
	@echo "Running tests..."
	@go test ./... || { echo "Tests failed"; exit 1; }

# Build the binary
build: $(GO_FILES)
	@echo "Building the binary..."
	@mkdir -p $(BUILD_DIR)
	@go build -o $(BIN_FILE) $(SOURCE_DIR) || { echo "Build failed"; exit 1; }

# Run vet and tests inside the Go container (no local Go needed)
test-docker:
	@echo "Running vet and tests in $(GO_IMAGE)..."
	@$(DOCKER_RUN) $(GO_IMAGE) sh -c "go vet ./... && go test ./..."

# Build the binary inside the Go container
build-docker:
	@echo "Building the binary in $(GO_IMAGE)..."
	@$(DOCKER_RUN) $(GO_IMAGE) go build -o $(BIN_FILE) $(SOURCE_DIR)

# Lint inside the golangci-lint container
lint-docker:
	@echo "Linting in $(LINT_IMAGE)..."
	@$(DOCKER_RUN) $(LINT_IMAGE) golangci-lint run ./...

# Clean up build artifacts
clean:
	@echo "Cleaning up..."
	@go clean -cache
	@rm -f $(BIN_FILE) || echo "Could not remove binary file"

# Release target
SOURCE_BRANCH ?= dev
TARGET_BRANCH ?= master

release:
ifndef VERSION
	$(error VERSION is not set. Usage: make release VERSION=v1.0.7)
endif
	@echo "Releasing $(VERSION): $(SOURCE_BRANCH) -> $(TARGET_BRANCH)"
	@git diff --quiet && git diff --cached --quiet || { echo "Worktree is dirty. Commit or stash changes first."; exit 1; }
	@git rev-parse $(VERSION) >/dev/null 2>&1 && { echo "Tag $(VERSION) already exists."; exit 1; } || true
	@git fetch origin
	@git checkout $(SOURCE_BRANCH)
	@git push origin $(SOURCE_BRANCH)
	@git checkout $(TARGET_BRANCH)
	@git pull --ff-only origin $(TARGET_BRANCH)
	@git merge --no-ff $(SOURCE_BRANCH) -m "Merge $(SOURCE_BRANCH) for $(VERSION)"
	@git push origin $(TARGET_BRANCH)
	@git tag $(VERSION)
	@git push origin $(VERSION)
	@git checkout $(SOURCE_BRANCH)
	@echo "Done. Watch: https://github.com/idesyatov/ssl-watch/actions"

# Help
help:
	@echo "Makefile for Golang projects"
	@echo "Usage:"
	@echo "  make all           - Format the code, run tests, and build the binary"
	@echo "  make format        - Format the Go source files according to Go standards"
	@echo "  make test          - Execute the unit tests for the Go package"
	@echo "  make build         - Compile the source code into a binary executable"
	@echo "  make test-docker   - Run vet and tests in the Go container (no local Go needed)"
	@echo "  make build-docker  - Build the binary in the Go container"
	@echo "  make lint-docker   - Run golangci-lint in its container"
	@echo "  make clean         - Remove all generated build artifacts and cached files"
	@echo "  make release       - Merge SOURCE_BRANCH -> TARGET_BRANCH, tag and push"
	@echo "                      (example: make release VERSION=v1.0.7)"
	@echo "                      Defaults: SOURCE_BRANCH=dev, TARGET_BRANCH=master"
	@echo "                      Worktree must be clean — commit your changes first."
	@echo "  make help          - Display this help message"