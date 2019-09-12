
build/kssh:
	go build -o build/kssh

build: build/kssh
	@mkdir -p build

deb:
	@rm -rf pkg-build
	go-bin-deb generate --arch $(shell go env GOARCH)
