TOOL?=vault-plugin-secrets-spiffe
EXTERNAL_TOOLS="mvdan.cc/gofumpt@v0.8.0" "golang.org/x/tools/cmd/goimports@v0.34.0" "gotest.tools/gotestsum@v1.12.3"
BUILD_TAGS?=${TOOL}
GOFMT_FILES?=$$(find . -name '*.go' | grep -v vendor)
# enable the plugin to use Enterprise plugin SDK and have license checking
# installed
BUILD_TAGS+=enterprise

default: dev

.PHONY: dev
dev: fmtcheck
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS)' sh -c "'$(CURDIR)/scripts/build.sh'"

.PHONY: test
test:
	gotestsum --format testname -- -tags='$(BUILD_TAGS)'  ./... -timeout=10m -count=1 || exit 1; \

.PHONY: test-race
test-race:
	gotestsum --format testname -- -tags='$(BUILD_TAGS)'  ./... -timeout=10m -count=1 -race || exit 1; \

.PHONY: cover
cover:
	go test -tags='$(BUILD_TAGS)' -cover -coverprofile=coverage.txt ./... || exit 1; \

.PHONY: bootstrap
bootstrap:
	@for tool in $(EXTERNAL_TOOLS) ; do \
		echo "Installing/Updating $$tool" ; \
		go install $$tool; \
	done

.PHONY: fmtcheck
fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

.PHONY: fmt
fmt:
	@goimports -w $(GOFMT_FILES)
	@gofumpt -w $(GOFMT_FILES)
