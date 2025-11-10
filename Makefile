TOOL?=vault-envelope-encryption-sdk
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

.PHONY: check-tools-external
check-tools-external:
	@$(CURDIR)/tools/tools.sh check-external

proto: check-tools-external
	@echo "==> Generating Go code from protobufs..."
	buf generate

	# No additional sed expressions should be added to this list. Going forward
	# we should just use the variable names chosen by protobuf. These are left
	# here for backwards compatibility, namely for SDK compilation.
	$(SED) -i -e 's/Id/ID/' -e 's/SPDX-License-IDentifier/SPDX-License-Identifier/' vault/request_forwarding_service.pb.go
	$(SED) -i -e 's/Idp/IDP/' -e 's/Url/URL/' -e 's/Id/ID/' -e 's/IDentity/Identity/' -e 's/EntityId/EntityID/' -e 's/Api/API/' -e 's/Qr/QR/' -e 's/Totp/TOTP/' -e 's/Mfa/MFA/' -e 's/Pingid/PingID/' -e 's/namespaceId/namespaceID/' -e 's/Ttl/TTL/' -e 's/BoundCidrs/BoundCIDRs/' -e 's/SPDX-License-IDentifier/SPDX-License-Identifier/' helper/identity/types.pb.go helper/identity/mfa/types.pb.go helper/storagepacker/types.pb.go sdk/plugin/pb/backend.pb.go sdk/logical/identity.pb.go vault/activity/activity_log.pb.go

	# Enterprise files
	$(SED) -i -e 's/Idp/IDP/' -e 's/Url/URL/' -e 's/Id/ID/' -e 's/IDentity/Identity/' -e 's/EntityId/EntityID/' -e 's/Api/API/' -e 's/Qr/QR/' -e 's/Totp/TOTP/' -e 's/Mfa/MFA/' -e 's/Pingid/PingID/' -e 's/protobuf:"/sentinel:"" protobuf:"/' -e 's/namespaceId/namespaceID/' -e 's/Ttl/TTL/' -e 's/SPDX-License-IDentifier/SPDX-License-Identifier/' vault/replication_services_ent.pb.go