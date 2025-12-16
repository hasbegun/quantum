# Quantum Cryptography Demonstrations
# - Shor's Algorithm Threat to RSA/ECDSA
# - BB84 Quantum Key Distribution

.PHONY: help build test shell clean \
        demo-rsa demo-ecdsa demo-threat demo-shors-cirq demo-qkd \
        dev dev-test dev-shell

# Default target
help:
	@echo "╔═══════════════════════════════════════════════════════════════════╗"
	@echo "║           Quantum Cryptography Demonstrations                     ║"
	@echo "╚═══════════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "  SHOR'S ALGORITHM (Quantum Threat to Classical Crypto):"
	@echo "  ───────────────────────────────────────────────────────"
	@echo "  make demo-rsa        Break RSA encryption with Shor's algorithm"
	@echo "  make demo-ecdsa      Break ECDSA signatures with Shor's algorithm"
	@echo "  make demo-threat     Complete quantum threat overview"
	@echo "  make demo-shors-cirq Shor's algorithm with Google Cirq circuits"
	@echo ""
	@echo "  QUANTUM KEY DISTRIBUTION:"
	@echo "  ─────────────────────────"
	@echo "  make demo-qkd      BB84 quantum key distribution demo"
	@echo ""
	@echo "  BUILD & TEST:"
	@echo "  ──────────────"
	@echo "  make build         Build Docker image"
	@echo "  make test          Run all tests"
	@echo "  make shell         Interactive Python shell"
	@echo "  make clean         Remove Docker resources"

# Build the Docker image
build:
	docker compose build qkd

# ═══════════════════════════════════════════════════════════════════════════
# SHOR'S ALGORITHM DEMOS
# ═══════════════════════════════════════════════════════════════════════════

demo-rsa: build
	@echo ""
	@echo "╔═══════════════════════════════════════════════════════════════════╗"
	@echo "║         SHOR'S ALGORITHM: BREAKING RSA ENCRYPTION                 ║"
	@echo "║                                                                   ║"
	@echo "║  This demo shows how quantum computers factor large numbers       ║"
	@echo "║  to completely break RSA encryption.                              ║"
	@echo "╚═══════════════════════════════════════════════════════════════════╝"
	@echo ""
	docker compose run --rm break-rsa

demo-ecdsa: build
	@echo ""
	@echo "╔═══════════════════════════════════════════════════════════════════╗"
	@echo "║         SHOR'S ALGORITHM: BREAKING ECDSA SIGNATURES               ║"
	@echo "║                                                                   ║"
	@echo "║  This demo shows how quantum computers solve discrete log         ║"
	@echo "║  to break ECDSA (used in Bitcoin, TLS, SSH).                      ║"
	@echo "╚═══════════════════════════════════════════════════════════════════╝"
	@echo ""
	docker compose run --rm break-ecdsa

demo-threat: build
	@echo ""
	@echo "╔═══════════════════════════════════════════════════════════════════╗"
	@echo "║              QUANTUM COMPUTING THREAT OVERVIEW                    ║"
	@echo "║                                                                   ║"
	@echo "║  Comprehensive demonstration of quantum threats to cryptography   ║"
	@echo "║  including timeline, mitigations, and post-quantum solutions.     ║"
	@echo "╚═══════════════════════════════════════════════════════════════════╝"
	@echo ""
	docker compose run --rm threat-overview

demo-shors-cirq: build
	@echo ""
	@echo "╔═══════════════════════════════════════════════════════════════════╗"
	@echo "║         SHOR'S ALGORITHM - QUANTUM CIRCUIT DEMO (Cirq)            ║"
	@echo "║                                                                   ║"
	@echo "║  Real quantum circuit implementation using Google Cirq:           ║"
	@echo "║  - Quantum Fourier Transform (QFT)                                ║"
	@echo "║  - Quantum period finding                                         ║"
	@echo "║  - Modular exponentiation circuits                                ║"
	@echo "╚═══════════════════════════════════════════════════════════════════╝"
	@echo ""
	docker compose run --rm qkd python examples/shors_cirq_demo.py

# ═══════════════════════════════════════════════════════════════════════════
# QKD DEMO
# ═══════════════════════════════════════════════════════════════════════════

demo-qkd: build
	@echo ""
	@echo "╔═══════════════════════════════════════════════════════════════════╗"
	@echo "║           BB84 QUANTUM KEY DISTRIBUTION DEMO                      ║"
	@echo "║                                                                   ║"
	@echo "║  Simulate secure key exchange using quantum mechanics.            ║"
	@echo "║  Detects eavesdropping through quantum measurement disturbance.   ║"
	@echo "╚═══════════════════════════════════════════════════════════════════╝"
	@echo ""
	docker compose run --rm qkd

# Alias for backward compatibility
run: demo-qkd

# ═══════════════════════════════════════════════════════════════════════════
# TESTING
# ═══════════════════════════════════════════════════════════════════════════

test: build
	docker compose run --rm --profile test test

test-shors: build
	docker compose run --rm qkd python -m pytest tests/test_shors.py -v

test-qkd: build
	docker compose run --rm qkd python -m pytest tests/test_bb84.py -v

# ═══════════════════════════════════════════════════════════════════════════
# DEVELOPMENT
# ═══════════════════════════════════════════════════════════════════════════

dev: build
	docker compose run --rm \
		-v $(PWD)/src:/app/src:ro \
		-v $(PWD)/examples:/app/examples:ro \
		qkd python demo.py

dev-test: build
	docker compose run --rm \
		-v $(PWD)/src:/app/src:ro \
		-v $(PWD)/tests:/app/tests:ro \
		-v $(PWD)/examples:/app/examples:ro \
		qkd python -m pytest tests/ -v

dev-shell: build
	docker compose run --rm \
		-v $(PWD)/src:/app/src \
		-v $(PWD)/tests:/app/tests \
		-v $(PWD)/examples:/app/examples \
		--profile dev shell

shell: build
	docker compose run --rm --profile dev shell

# Clean up containers and images
clean:
	docker compose down --rmi local --volumes --remove-orphans
	@echo "Cleaned up Docker resources"
