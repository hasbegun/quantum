.PHONY: build test test-mldsa test-slhdsa dev shell \
        demo-api demo-document demo-compare clean help

IMAGE_NAME := dsa
CONTAINER_NAME := dsa-dev

help:
	@echo "Post-Quantum DSA (FIPS 204 & 205) Makefile"
	@echo "==========================================="
	@echo ""
	@echo "Build & Test:"
	@echo "  make build        - Build the Docker image"
	@echo "  make test         - Run all tests"
	@echo "  make test-mldsa   - Run ML-DSA tests only"
	@echo "  make test-slhdsa  - Run SLH-DSA tests only"
	@echo "  make dev          - Run tests with mounted source"
	@echo ""
	@echo "Examples:"
	@echo "  make demo-api     - API authentication (ML-DSA)"
	@echo "  make demo-document- Document signing (SLH-DSA)"
	@echo "  make demo-compare - Compare ML-DSA vs SLH-DSA"
	@echo ""
	@echo "Development:"
	@echo "  make shell        - Interactive Python shell"
	@echo "  make clean        - Remove Docker resources"

build:
	docker build -t $(IMAGE_NAME) .

test: build
	docker run --rm $(IMAGE_NAME) python -m pytest tests/ -v

test-mldsa: build
	docker run --rm $(IMAGE_NAME) python -m pytest tests/test_mldsa.py -v

test-slhdsa: build
	docker run --rm $(IMAGE_NAME) python -m pytest tests/test_slhdsa.py -v --tb=short

dev:
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	docker run --rm \
		--name $(CONTAINER_NAME) \
		-v $(PWD)/src:/app/src:ro \
		-v $(PWD)/tests:/app/tests:ro \
		$(IMAGE_NAME) \
		python -m pytest tests/ -v

shell: build
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	docker run -it --rm \
		--name $(CONTAINER_NAME) \
		-v $(PWD)/src:/app/src \
		-v $(PWD)/tests:/app/tests \
		$(IMAGE_NAME) \
		python

demo-api: build
	docker run --rm $(IMAGE_NAME) python examples/api_authentication.py

demo-document: build
	docker run --rm $(IMAGE_NAME) python examples/document_signing.py

demo-compare: build
	docker run --rm $(IMAGE_NAME) python examples/comparison.py

clean:
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	@docker rmi -f $(IMAGE_NAME) 2>/dev/null || true
	@echo "Cleaned up Docker resources"
