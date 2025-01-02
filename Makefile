APP_NAME=sslwatch
SRC_FILE=main.go

BIN_DIR=./bin
BIN_FILE=$(BIN_DIR)/$(APP_NAME)

.PHONY: all build clean test

all: test build 

build: $(BIN_FILE)

$(BIN_FILE): $(SRC_FILE)
	@echo "Building the application..."
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_FILE) $(SRC_FILE)

test:
	@echo "Running tests..."
	go test -v

clean:
	@echo "Cleaning up..."
	go clean
	rm -f $(BIN_FILE)