# Makefile for HTTPRunner

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
