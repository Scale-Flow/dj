BINARY   := dj
MODULE   := github.com/scale-flow/dj
VERSION  := 0.1.0
LDFLAGS  := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test lint install clean

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/$(BINARY)

test:
	go test ./...

lint:
	golangci-lint run ./...

install:
	go install $(LDFLAGS) ./cmd/$(BINARY)

clean:
	rm -rf bin/
