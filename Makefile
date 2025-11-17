.PHONY: build run clean docker-build docker-push test fmt vet

# Variables
BINARY_NAME=docktail
DOCKER_IMAGE=ghcr.io/marvinvr/docktail
VERSION?=latest

# Build the binary
build:
	go build -o $(BINARY_NAME) .

# Run the application locally
run: build
	./$(BINARY_NAME)

# Clean build artifacts
clean:
	go clean
	rm -f $(BINARY_NAME)

# Build Docker image
docker-build:
	docker build -t $(DOCKER_IMAGE):$(VERSION) .

# Push Docker image
docker-push: docker-build
	docker push $(DOCKER_IMAGE):$(VERSION)

# Run tests
test:
	go test -v ./...

# Format code
fmt:
	go fmt ./...

# Run go vet
vet:
	go vet ./...

# Install dependencies
deps:
	go mod download
	go mod tidy

# Run all checks
check: fmt vet test

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -o $(BINARY_NAME)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY_NAME)-darwin-arm64 .

# Start docker-compose
up:
	docker compose up -d

# Stop docker-compose
down:
	docker compose down

# View logs
logs:
	docker logs -f docktail
