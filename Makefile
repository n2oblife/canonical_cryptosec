# ==============================================================================
# Makefile: Canonical Linux Cryptography & Security Server
# ==============================================================================

# Toolchain definitions
CC          ?= gcc
RM          := rm -rf
MKDIR       := mkdir -p

# Directory Structure
SRC_DIR     := src
INC_DIR     := include
CERTS_DIR   := certs
SCRIPTS_DIR := scripts
TESTS_DIR   := tests

BUILD_DIR	:= build
BIN_DIR     := $(BUILD_DIR)/bin
OBJ_DIR     := $(BUILD_DIR)/obj

# Binary Target
TARGET      := $(BIN_DIR)/crypto_server

# Source files and Object mapping
SRCS        := $(SRC_DIR)/main.c $(SRC_DIR)/crypto.c $(SRC_DIR)/executor.c
OBJS        := $(OBJ_DIR)/main.o $(OBJ_DIR)/crypto.o $(OBJ_DIR)/executor.o

# Default profile is 'dev'. To build for prod: make prod
PROFILE ?= dev

# Script and ccertification
TEST_SCRIPTS_DIR	?= test_scripts
SCRIPT 				?= hello_world
SCRIPT_PATH 		?= $(TEST_SCRIPTS_DIR)/$(SCRIPT)
PROTO  				?= uds
KEY_DIR				?= certs/keys
KEY    				?= valid_codesign.key
KEY_PATH			?= $(KEY_DIR)/$(KEY)


PYTEST_CACHE	?= .pytest_cache
VENV			?= venv

ifeq ($(PROFILE), prod)
    PROFILE_FLAGS := -DENV_PRODUCTION
    $(info ==> Building with PRODUCTION sandbox limits)
else
    PROFILE_FLAGS := 
    $(info ==> Building with DEVELOPMENT sandbox limits)
endif

# Canonical / Ubuntu Security Hardening & Standard Flags
# -D_FORTIFY_SOURCE=2: Buffer overflow detection for libc calls
# -fstack-protector-strong: Stack canary protection
# -fPIE / -pie: Position Independent Executable (ASLR support)
# -Wl,-z,relro,-z,now: Read-only relocations & immediate binding (prevents GOT overwrite)
SECURITY_FLAGS := -fstack-protector-strong \
                  -D_FORTIFY_SOURCE=2 \
                  -Wformat -Wformat-security \
                  -fPIE

WARN_FLAGS     := -Wall -Wextra -Werror -pedantic -Wconversion -Wshadow
BASE_CFLAGS    := -std=gnu11 -I$(INC_DIR) $(WARN_FLAGS) $(SECURITY_FLAGS) $(PROFILE_FLAGS)
RELEASE_CFLAGS := $(BASE_CFLAGS) -O2
DEBUG_CFLAGS   := $(BASE_CFLAGS) -O0 -g3 -DDEBUG -fsanitize=address,undefined --coverage -O0 -g -U_FORTIFY_SOURCE

# Linker flags
LDFLAGS        := -lcrypto -pie -Wl,-z,relro,-z,now
DEBUG_LDFLAGS  := $(LDFLAGS) -fsanitize=address,undefined

# Default build profile: Release
CFLAGS         := $(RELEASE_CFLAGS)


# ==============================================================================
# Primary User-Facing Targets
# ==============================================================================

.PHONY: all prod debug release prod

all: release

release: $(TARGET)

# Prod target explicitly forces the prod profile
prod: PROFILE := prod
prod: clean_objs release

debug: CFLAGS := $(DEBUG_CFLAGS)
debug: LDFLAGS := $(DEBUG_LDFLAGS)
debug: clean_objs $(TARGET)

# ==============================================================================
# Linking Stage
# ==============================================================================

$(TARGET): $(OBJS) | $(BIN_DIR)
	@echo "==> [LINK] $@"
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# ==============================================================================
# Granular Compilation Targets
# ==============================================================================

$(OBJ_DIR)/main.o: $(SRC_DIR)/main.c $(INC_DIR)/server.h $(INC_DIR)/crypto.h $(INC_DIR)/executor.h | $(OBJ_DIR)
	@echo "==> [CC] $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/crypto.o: $(SRC_DIR)/crypto.c $(INC_DIR)/crypto.h | $(OBJ_DIR)
	@echo "==> [CC] $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/executor.o: $(SRC_DIR)/executor.c $(INC_DIR)/executor.h | $(OBJ_DIR)
	@echo "==> [CC] $<"
	$(CC) $(CFLAGS) -c $< -o $@

# Convenience aliases to compile individual modules
compile-main: $(OBJ_DIR)/main.o
compile-crypto: $(OBJ_DIR)/crypto.o
compile-executor: $(OBJ_DIR)/executor.o

# ==============================================================================
# Directory Setup
# ==============================================================================

$(OBJ_DIR):
	@$(MKDIR) $(OBJ_DIR)

$(BIN_DIR):
	@$(MKDIR) $(BIN_DIR)

# ==============================================================================
# Automation & Environment Targets
# ==============================================================================

.PHONY: pki test

# Generates the test PKI certificates
pki:
	@echo "==> Generating PKI test certificates..."
	@bash $(SCRIPTS_DIR)/gen_pki.sh

# Runs the integration test suite using pytest
test: release pki
	@echo "==> Executing test suite via pytest..."
	@python3 -m pytest tests/ -v

# ==============================================================================
# Execution Targets
# ==============================================================================

.PHONY: run-uds run-tcp

# Run the server using a UNIX Domain Socket
run-uds: release pki
	@echo "==> Starting server on UNIX Domain Socket (/tmp/sec_server.sock)..."
	./$(BIN_DIR)/crypto_server -c certs/trusted -u /tmp/sec_server.sock

# Run the server using a TCP port
run-tcp: release pki
	@echo "==> Starting server on TCP port 8080..."
	./$(BIN_DIR)/crypto_server -c certs/trusted -p 8080

# ==============================================================================
# Manual Client Testing CLI
# ==============================================================================

.PHONY: sign send trigger

sign:
	@echo "==> Executing signing script..."
	@bash scripts/sign_script.sh $(KEY_PATH) $(SCRIPT_PATH).sh payload.txt

send:
	@if ! command -v socat >/dev/null 2>&1; then echo "[-] Error: 'socat' is not installed. Please install it (e.g., sudo pacman -S socat)."; exit 1; fi
	@if [ ! -f payload.txt ]; then echo "[-] Error: payload.txt not found. Run 'make sign' first."; exit 1; fi
	@if [ "$(PROTO)" = "tcp" ]; then \
		echo "==> Sending via TCP to 127.0.0.1:8080..."; \
		socat - TCP4:127.0.0.1:8080 < payload.txt; \
	else \
		echo "==> Sending via UDS to /tmp/sec_server.sock..."; \
		socat - UNIX-CONNECT:/tmp/sec_server.sock < payload.txt; \
	fi

trigger: sign send

# ==============================================================================
# Code Coverage (gcov + lcov driven by Python tests)
# ==============================================================================
COVERAGE_FLAGS := --coverage -O0 -g -U_FORTIFY_SOURCE

.PHONY: coverage

coverage: CFLAGS := $(BASE_CFLAGS) $(COVERAGE_FLAGS)
coverage: LDFLAGS := $(LDFLAGS) $(COVERAGE_FLAGS)
coverage: clean_objs release pki
	@echo "==> Running integration tests to generate C coverage data..."
	@python3 -m pytest tests/ -v
	@echo "==> Processing coverage data with lcov..."
	@mkdir -p $(BUILD_DIR)/coverage
	@lcov --capture --directory $(OBJ_DIR) --output-file $(BUILD_DIR)/coverage/coverage.info --ignore-errors inconsistent
	@echo "==> Filtering out system headers and external libraries..."
	@lcov --remove $(BUILD_DIR)/coverage/coverage.info '/usr/*' --output-file $(BUILD_DIR)/coverage/coverage_filtered.info --ignore-errors inconsistent
	@echo "==> Generating HTML report..."
	@genhtml $(BUILD_DIR)/coverage/coverage_filtered.info --output-directory $(BUILD_DIR)/coverage/report
	@echo ""
	@echo "======================================================================"
	@echo "SUCCESS: Coverage report generated!"
	@echo "Open this file in browser: file://$(shell pwd)/$(BUILD_DIR)/coverage/report/index.html"
	@echo "======================================================================"

# ==============================================================================
# Housekeeping
# ==============================================================================

.PHONY: clean clean_objs distclean clean_coverage clean_deep

clean_coverage:
	@echo "==> Cleaning coverage artifacts..."
	@$(RM) $(OBJ_DIR)/*.gcno $(OBJ_DIR)/*.gcda $(BUILD_DIR)/coverage .coverage

clean_objs:
	@echo "==> Cleaning object files..."
	@echo "==> Cleaning Python cache..."
	@$(RM) $(OBJ_DIR) $(PYTEST_CACHE) $(VENV)/* */__pycache__

clean:
	@echo "==> Cleaning build artifacts..."
	@$(RM) $(OBJ_DIR) $(BIN_DIR) payload.txt

distclean: clean clean_coverage
	@echo "==> Removing generated certs and temporary test keys..."
	@$(RM) $(CERTS_DIR)/keys $(CERTS_DIR)/trusted $(CERTS_DIR)/*.crt $(CERTS_DIR)/*.ext $(CERTS_DIR)/*.srl

clean_deep: clean distclean clean_objs clean_coverage 

# ==============================================================================
# Help Menu
# ==============================================================================

.PHONY: help

help:
	@echo "Canonical Cryptography & Security Server Build System"
	@echo ""
	@echo "Build Targets:"
	@echo "  make              - Build release binary with development limits ($(TARGET))"
	@echo "  make prod         - Build release binary with strict production limits"
	@echo "  make debug        - Build with debug symbols and sanitizers (ASan/UBSan)"
	@echo "  make compile-<m>  - Compile a single module (main, crypto, executor)"
	@echo ""
	@echo "Testing & Coverage:"
	@echo "  make pki          - Generate test CA, valid certs, and invalid certs"
	@echo "  make test         - Run the end-to-end Python integration test suite"
	@echo "  make coverage     - Run tests and generate HTML C code coverage reports"
	@echo ""
	@echo "Execution Targets:"
	@echo "  make run-uds      - Start server on UNIX Domain Socket (/tmp/sec_server.sock)"
	@echo "  make run-tcp      - Start server on TCP port 8080"
	@echo ""
	@echo "Manual Client CLI:"
	@echo "  make sign         - Sign a script (Args: SCRIPT=name KEY=keyfile)"
	@echo "  make send         - Send payload to server (Args: PROTO=uds|tcp)"
	@echo "  make trigger      - Sign and send in one step"
	@echo ""
	@echo "Housekeeping:"
	@echo "  make clean        - Remove standard build artifacts (obj/, bin/, payload.txt)"
	@echo "  make clean_cov    - Remove coverage data (.gcno, .gcda, HTML reports)"
	@echo "  make distclean    - Remove build artifacts and generated test certificates"
	@echo "  make clean_deep   - Run clean, distclean, and clean_coverage together"