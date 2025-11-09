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
release:
ifndef VERSION
	$(error VERSION is not set. Please provide a version with VERSION=v1.0.0)
endif
ifndef BRANCH
	$(error BRANCH is not set. Please provide a branch with BRANCH=dev)
endif
	@echo "Releasing version $(VERSION) to branch $(BRANCH)..."
	@git add .
	@git commit -m "[feat] release $(VERSION)" || { echo "Commit failed"; exit 1; }
	@git tag $(VERSION)
	@git push origin $(BRANCH) --tags || { echo "Push failed"; exit 1; }

# Help
help:
	@echo "Makefile for Golang projects"
	@echo "Usage:"
	@echo "  make all      - Format the code, run tests, and build the binary"
	@echo "  make format   - Format the Go source files according to Go standards"
	@echo "  make test     - Execute the unit tests for the Go package"
	@echo "  make build    - Compile the source code into a binary executable"
	@echo "  make clean    - Remove all generated build artifacts and cached files"
	@echo "  make release  - Commit changes, tag the version, and push to the remote repository"
	@echo "  make help     - Display this help message"