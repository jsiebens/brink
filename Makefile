SHELL := bash
Version := $(shell git describe --tags --dirty)
# Version := "dev"
GitCommit := $(shell git rev-parse HEAD)
LDFLAGS := "-s -w -X github.com/jsiebens/proxiro/internal/version.Version=$(Version) -X github.com/jsiebens/proxiro/internal/version.GitCommit=$(GitCommit)"
.PHONY: all

.PHONY: build
build:
	go build -ldflags $(LDFLAGS) -a -installsuffix cgo cmd/proxiro/main.go

.PHONY: dist
dist:
	mkdir -p dist
	GOOS=linux go build -ldflags $(LDFLAGS) -a -installsuffix cgo -o dist/proxiro cmd/proxiro/main.go
	GOOS=darwin go build -ldflags $(LDFLAGS) -a -installsuffix cgo -o dist/proxiro-darwin cmd/proxiro/main.go
	GOOS=linux GOARCH=arm64 go build -ldflags $(LDFLAGS) -a -installsuffix cgo -o dist/proxiro-arm64 cmd/proxiro/main.go
	GOOS=linux GOARCH=arm GOARM=6 go build -ldflags $(LDFLAGS) -a -installsuffix cgo -o dist/proxiro-armhf cmd/proxiro/main.go
	GOOS=windows go build -ldflags $(LDFLAGS) -a -installsuffix cgo -o dist/proxiro.exe cmd/proxiro/main.go

.PHONY: hash
hash:
	for f in dist/proxiro*; do shasum -a 256 $$f > $$f.sha256; done