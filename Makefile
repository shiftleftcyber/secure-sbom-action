GO ?= go
GOFMT ?= gofmt "-s"
GO_VERSION=$(shell $(GO) version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f2)
PACKAGES ?= $(shell $(GO) list ./...)
VETPACKAGES ?= $(shell $(GO) list ./... | grep -v /examples/)
GOFILES := $(shell find . -name "*.go")
TESTFOLDER := $(shell $(GO) list ./... | grep -E 'utils$$')
DOCKER ?= docker
TEST_FILES := $(shell find . -name '*_test.go')
SWAG ?= swag
DOCKER_REGISTRY ?= "northamerica-northeast2-docker.pkg.dev/shiftleftcyber/shiftleftcyber"

.PHONY: test
test:
	@echo "Starting test process..."
	@mkdir -p coverage
	@packages=$$(go list ./...); \
	for pkg in $${packages}; do \
	    echo "Running tests in $${pkg}"; \
	    $(GO) test -v $(TESTTAGS) -covermode=count -coverprofile="coverage/$${pkg##*/}.out" "$${pkg}"; \
	done
	@echo "Combining coverage profiles..."
	gocovmerge coverage/*.out > coverage/merged.out
	@echo "Finished test process."

.PHONY: fmt
fmt:
	$(GOFMT) -w $(GOFILES)

.PHONY: fmt-check
fmt-check:
	@diff=$$($(GOFMT) -d $(GOFILES)); \
	if [ -n "$$diff" ]; then \
		echo "Please run 'make fmt' and commit the result:"; \
		echo "$${diff}"; \
		exit 1; \
	fi;

.PHONY: lint
lint:
	@DOCKER run --rm -v $(shell pwd):/app -w /app golangci/golangci-lint:v2.1.6 golangci-lint run ./...

.PHONY: clean
clean:
	@find . -name 'profile.out' -exec rm -f {} +
	@rm -rf secure-sbom-action

.PHONY: build
build:
	$(GO) build -o secure-sbom-action cmd/main.go

.PHONY: build-docker
build-docker:
	$(DOCKER) build --tag secure-sbom-action:dev .

.PHONY: docker-run
docker-run:
	$(DOCKER) run --rm --workdir /root -v $(PWD)/sboms:/root/sboms --env-file .env secure-sbom-action:dev

.PHONY: docker-debug
docker-debug:
	$(DOCKER) run --rm -it --workdir /root -v $(PWD)/sboms:/root/sboms --env-file .env --entrypoint ash secure-sbom-action:dev

.PHONY: docker-lint
docker-lint:
	$(DOCKER) run --rm -it \
		-v "$(shell pwd)":/build \
		--workdir /build \
		hadolint/hadolint:v2.12.0-alpine hadolint Dockerfile*

.PHONY: markdown-lint
markdown-lint:
	$(DOCKER) run --rm -it \
		-v "$(shell pwd)":/build \
		--workdir /build \
		markdownlint/markdownlint:0.13.0 *.md
