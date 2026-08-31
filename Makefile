.PHONY: build test test-go test-python fmt analyzer-image

build:
	go build -o bin/jaq ./cmd/jaq

test: test-go test-python

test-go:
	go test ./...

test-python:
	PYTHONPATH=python python3 -m unittest discover -s python/tests -v

fmt:
	gofmt -w $$(find cmd internal -name '*.go' -type f)

analyzer-image:
	docker build --pull -t jaq-ghidra:12.1.3 analysis
