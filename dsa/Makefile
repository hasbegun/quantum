.PHONY: build build-py build-cpp test test-py test-cpp \
        test-mldsa test-slhdsa test-mldsa-cpp test-slhdsa-cpp \
        dev shell demo-api demo-document demo-compare demo-cpp clean help

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
	@echo "Examples:"
	@echo "  make demo-api     - API authentication (ML-DSA Python)"
	@echo "  make demo-document- Document signing (SLH-DSA Python)"
	@echo "  make demo-compare - Compare ML-DSA vs SLH-DSA (Python)"
	@echo "  make demo-cpp     - Run C++ ML-DSA demo"
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

# Demo targets
demo-api: build-py
	docker run --rm $(IMAGE_NAME_PY) python examples/api_authentication.py

demo-document: build-py
	docker run --rm $(IMAGE_NAME_PY) python examples/document_signing.py

demo-compare: build-py
	docker run --rm $(IMAGE_NAME_PY) python examples/comparison.py

demo-cpp: build-cpp
	docker run --rm $(IMAGE_NAME_CPP) ./build/mldsa_demo

# Cleanup
clean:
	@docker rm -f $(CONTAINER_NAME) 2>/dev/null || true
	@docker rmi -f $(IMAGE_NAME_PY) 2>/dev/null || true
	@docker rmi -f $(IMAGE_NAME_CPP) 2>/dev/null || true
	@echo "Cleaned up Docker resources"
