.PHONY: build test test-go test-python fmt sandbox-image

build:
	go build -o bin/jaq ./cmd/jaq

test: test-go test-python

test-go:
	go test ./...

test-python:
	PYTHONPATH=python python3 -m unittest discover -s python/tests -v

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

sandbox-image:
	docker build --pull --platform linux/amd64 -t jaq-radare2:6.2.0-mcp1.8.6 analysis
