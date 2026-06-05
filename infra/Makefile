# infra/Makefile — build + scan targets for the ghidra-mcp container images.
#
# These targets wrap the GATED commands (image build/pull, dependency install, isolation runs).
# WS3 does NOT execute them — they are the documented, repeatable invocations a maintainer/CI runs
# AFTER the supply-chain gate (digests + lockfile vetted and pinned). Mirrors deploy/README.md.
#
# Usage (from repo root, after approval):  make -f infra/Makefile <target>
#
# Rules: std-supplychain (digest pin, SBOM, sign), workflow-cicd (scan gates), ADR-003/004.

# --- Pinned references (set after the supply-chain gate; placeholders mirror the Containerfiles) ---
WORKER_IMAGE  ?= ghcr.io/OWNER/ghidra-mcp-worker
SERVER_IMAGE  ?= ghcr.io/OWNER/ghidra-mcp-server
TAG           ?= dev
GHIDRA_VERSION    ?= REPLACE_WITH_GHIDRA_11x_PATCH_VERSION
GHIDRA_ZIP_URL    ?= REPLACE_WITH_GHIDRA_RELEASE_ZIP_URL
GHIDRA_ZIP_SHA256 ?= REPLACE_WITH_GHIDRA_RELEASE_ZIP_SHA256

ENGINE ?= podman

.PHONY: help
help:
	@echo "Targets (all GATED — run after supply-chain approval):"
	@echo "  lint-dockerfiles   hadolint the Containerfiles"
	@echo "  build-worker       build the hardened Ghidra worker image"
	@echo "  build-server       build the MCP control-plane server image"
	@echo "  build              build both images"
	@echo "  scan-images        Trivy image scan (fail on HIGH/CRITICAL)"
	@echo "  scan-config        Trivy IaC/misconfig scan"
	@echo "  sbom               generate CycloneDX SBOMs for both images"
	@echo "  verify-isolation   ADR-004 acceptance harness (needs pinned WORKER_IMAGE)"
	@echo "  all-checks         lint + build + scan + sbom (the pre-release bundle)"

.PHONY: lint-dockerfiles
lint-dockerfiles:
	hadolint --config infra/hadolint.yaml Containerfile.worker Containerfile.server

.PHONY: build-worker
build-worker:
	$(ENGINE) build -f Containerfile.worker \
	  --build-arg GHIDRA_VERSION=$(GHIDRA_VERSION) \
	  --build-arg GHIDRA_ZIP_URL=$(GHIDRA_ZIP_URL) \
	  --build-arg GHIDRA_ZIP_SHA256=$(GHIDRA_ZIP_SHA256) \
	  -t $(WORKER_IMAGE):$(TAG) .

.PHONY: build-server
build-server:
	$(ENGINE) build -f Containerfile.server -t $(SERVER_IMAGE):$(TAG) .

.PHONY: build
build: build-worker build-server

.PHONY: scan-images
scan-images:
	trivy image --config infra/trivy.yaml $(WORKER_IMAGE):$(TAG)
	trivy image --config infra/trivy.yaml $(SERVER_IMAGE):$(TAG)

.PHONY: scan-config
scan-config:
	trivy config --config infra/trivy.yaml .

.PHONY: sbom
sbom:
	trivy image --format cyclonedx --output sbom-worker.cdx.json $(WORKER_IMAGE):$(TAG)
	trivy image --format cyclonedx --output sbom-server.cdx.json $(SERVER_IMAGE):$(TAG)

.PHONY: verify-isolation
verify-isolation:
	GHIDRA_MCP_WORKER_IMAGE=$(WORKER_IMAGE):$(TAG) deploy/verify-isolation.sh

.PHONY: all-checks
all-checks: lint-dockerfiles build scan-images scan-config sbom
