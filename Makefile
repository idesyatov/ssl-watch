# Makefile for Golang projects

# Variables
BINARY_NAME = ssl-watch
SOURCE_DIR = ./
BUILD_DIR = ./bin
GO_FILES = $(wildcard $(SOURCE_DIR)/*.go)
BIN_FILE = $(BUILD_DIR)/$(BINARY_NAME)

# Default target
.PHONY: all format test build clean
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
	@echo "  make clean         - Remove all generated build artifacts and cached files"
	@echo "  make release       - Merge SOURCE_BRANCH -> TARGET_BRANCH, tag and push"
	@echo "                      (example: make release VERSION=v1.0.7)"
	@echo "                      Defaults: SOURCE_BRANCH=dev, TARGET_BRANCH=master"
	@echo "                      Worktree must be clean — commit your changes first."
	@echo "  make help          - Display this help message"