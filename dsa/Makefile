.PHONY: build build-py build-cpp test test-py test-cpp \
        test-mldsa test-slhdsa test-mldsa-cpp test-slhdsa-cpp \
        test-kat test-kat-mldsa test-kat-slhdsa \
        dev shell demo-api demo-document demo-compare demo-cpp \
        cert-mldsa cert-slhdsa clean help

# Docker image names
IMAGE_NAME_PY := dsa-py
IMAGE_NAME_CPP := dsa-cpp
CONTAINER_NAME := dsa-dev

help:
	@echo "Post-Quantum DSA (FIPS 204 & 205) Makefile"
	@echo "==========================================="
	@echo ""
	@echo "Build:"
	@echo "  make build        - Build all Docker images"
	@echo "  make build-py     - Build Python Docker image"
	@echo "  make build-cpp    - Build C++ Docker image"
	@echo ""
	@echo "Test:"
	@echo "  make test         - Run all tests (Python + C++)"
	@echo "  make test-py      - Run all Python tests"
	@echo "  make test-cpp     - Run all C++ tests"
	@echo "  make test-mldsa   - Run ML-DSA Python tests only"
	@echo "  make test-slhdsa  - Run SLH-DSA Python tests only"
	@echo "  make test-mldsa-cpp   - Run ML-DSA C++ tests only"
	@echo "  make test-slhdsa-cpp  - Run SLH-DSA C++ tests only"
	@echo ""
	@echo "NIST KAT Tests (C++):"
	@echo "  make test-kat         - Run all NIST KAT tests"
	@echo "  make test-kat-mldsa   - Run ML-DSA NIST KAT tests"
	@echo "  make test-kat-slhdsa  - Run SLH-DSA NIST KAT tests"
	@echo ""
	@echo "Examples:"
	@echo "  make demo-api     - API authentication (ML-DSA Python)"
	@echo "  make demo-document- Document signing (SLH-DSA Python)"
	@echo "  make demo-compare - Compare ML-DSA vs SLH-DSA (Python)"
	@echo "  make demo-cpp     - Run C++ ML-DSA + SLH-DSA demo"
	@echo ""
	@echo "Certificate Examples (C++):"
	@echo "  make cert-mldsa   - ML-DSA certificate example"
	@echo "  make cert-slhdsa  - SLH-DSA certificate example"
	@echo ""
	@echo "Key Generation (saves to ./keys/):"
	@echo "  make keygen-mldsa44     - Generate ML-DSA-44 key pair"
	@echo "  make keygen-mldsa65     - Generate ML-DSA-65 key pair"
	@echo "  make keygen-mldsa87     - Generate ML-DSA-87 key pair"
	@echo "  make keygen-slhdsa      - Generate SLH-DSA-SHAKE-128f key pair"
	@echo "  make keygen-slhdsa-small- Generate SLH-DSA-SHAKE-128s key pair"
	@echo ""
	@echo "Development:"
	@echo "  make dev          - Run Python tests with mounted source"
	@echo "  make shell        - Interactive Python shell"
	@echo "  make clean        - Remove Docker resources"

# Build targets
build: build-py build-cpp

build-py:
	docker build -t $(IMAGE_NAME_PY) -f Dockerfile .

build-cpp:
	docker build -t $(IMAGE_NAME_CPP) -f Dockerfile.cpp .

# Test targets
test: test-py test-cpp

test-py: build-py
	docker run --rm $(IMAGE_NAME_PY) python -m pytest tests/py/ -v

test-cpp: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/test_mldsa
	docker run --rm $(IMAGE_NAME_CPP) ./build/test_slhdsa

test-mldsa: build-py
	docker run --rm $(IMAGE_NAME_PY) python -m pytest tests/py/test_mldsa.py -v

test-slhdsa: build-py
	docker run --rm $(IMAGE_NAME_PY) python -m pytest tests/py/test_slhdsa.py -v --tb=short

test-mldsa-cpp: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/test_mldsa

test-slhdsa-cpp: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/test_slhdsa

# NIST KAT Tests (FIPS 204 & 205 compliance)
test-kat: test-kat-mldsa test-kat-slhdsa

test-kat-mldsa: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/test_mldsa_kat

test-kat-slhdsa: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/test_slhdsa_kat

# Development
dev:
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	docker run --rm \
		--name $(CONTAINER_NAME) \
		-v $(PWD)/src:/app/src:ro \
		-v $(PWD)/tests:/app/tests:ro \
		$(IMAGE_NAME_PY) \
		python -m pytest tests/py/ -v

shell: build-py
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	docker run -it --rm \
		--name $(CONTAINER_NAME) \
		-v $(PWD)/src:/app/src \
		-v $(PWD)/tests:/app/tests \
		$(IMAGE_NAME_PY) \
		python

# Key generation targets (with mounted volume)
keygen: build-py
	@echo "Usage: make keygen-mldsa44, keygen-mldsa65, keygen-slhdsa, etc."
	@echo "Keys will be saved to ./keys/ directory"

keygen-mldsa44: build-py
	@mkdir -p keys
	docker run --rm -v $(PWD)/keys:/keys $(IMAGE_NAME_PY) python examples/py/generate_keys.py mldsa44 /keys

keygen-mldsa65: build-py
	@mkdir -p keys
	docker run --rm -v $(PWD)/keys:/keys $(IMAGE_NAME_PY) python examples/py/generate_keys.py mldsa65 /keys

keygen-mldsa87: build-py
	@mkdir -p keys
	docker run --rm -v $(PWD)/keys:/keys $(IMAGE_NAME_PY) python examples/py/generate_keys.py mldsa87 /keys

keygen-slhdsa: build-py
	@mkdir -p keys
	docker run --rm -v $(PWD)/keys:/keys $(IMAGE_NAME_PY) python examples/py/generate_keys.py slh-shake-128f /keys

keygen-slhdsa-small: build-py
	@mkdir -p keys
	docker run --rm -v $(PWD)/keys:/keys $(IMAGE_NAME_PY) python examples/py/generate_keys.py slh-shake-128s /keys

# Demo targets
demo-api: build-py
	docker run --rm $(IMAGE_NAME_PY) python examples/py/api_authentication.py

demo-document: build-py
	docker run --rm $(IMAGE_NAME_PY) python examples/py/document_signing.py

demo-compare: build-py
	docker run --rm $(IMAGE_NAME_PY) python examples/py/comparison.py

demo-cpp: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/mldsa_demo

# Certificate example targets (C++)
cert-mldsa: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/mldsa_cert_example

cert-slhdsa: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/slhdsa_cert_example

# Cleanup
clean:
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	@docker rmi -f $(IMAGE_NAME_PY) 2>/dev/null || true
	@docker rmi -f $(IMAGE_NAME_CPP) 2>/dev/null || true
	@echo "Cleaned up Docker resources"
