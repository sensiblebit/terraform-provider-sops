export CGO_ENABLED = 0

default: build

style:
	@echo ">> checking code style"
	! gofmt -d $(shell find . -name '*.go' -print) | grep '^'

vet:
	@echo ">> vetting code"
	go vet ./...

test:
	@echo ">> testing code"
	go test -v ./...

build:
	@echo ">> building binaries"
	go build -o terraform-provider-sops

generate-documentation:
	cd tools; go generate ./...

crossbuild:
	goreleaser build --snapshot --clean

snapshot:
	goreleaser release --snapshot --clean --skip=sign

release:
	goreleaser release --clean

.PHONY: default style vet test build crossbuild snapshot release generate-documentation
