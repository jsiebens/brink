SHELL := bash
Version := $(shell git describe --tags --dirty)
# Version := "dev"
GitCommit := $(shell git rev-parse HEAD)
LDFLAGS := "-s -w -X github.com/jsiebens/brink/internal/version.Version=$(Version) -X github.com/jsiebens/brink/internal/version.GitCommit=$(GitCommit)"
.PHONY: all

.PHONY: build
build:
	go build -ldflags $(LDFLAGS) -a -installsuffix cgo cmd/brink/main.go

.PHONY: dist
dist:
	mkdir -p dist
	GOOS=linux go build -ldflags $(LDFLAGS) -a -installsuffix cgo -o dist/brink cmd/brink/main.go
	GOOS=darwin go build -ldflags $(LDFLAGS) -a -installsuffix cgo -o dist/brink-darwin cmd/brink/main.go
	GOOS=linux GOARCH=arm64 go build -ldflags $(LDFLAGS) -a -installsuffix cgo -o dist/brink-arm64 cmd/brink/main.go
	GOOS=linux GOARCH=arm GOARM=6 go build -ldflags $(LDFLAGS) -a -installsuffix cgo -o dist/brink-armhf cmd/brink/main.go
	GOOS=windows go build -ldflags $(LDFLAGS) -a -installsuffix cgo -o dist/brink.exe cmd/brink/main.go

.PHONY: hash
hash:
	for f in dist/brink*; do shasum -a 256 $$f > $$f.sha256; done