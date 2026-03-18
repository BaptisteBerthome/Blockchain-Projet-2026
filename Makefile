CC = gcc
ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

BUILD_DIR = $(ROOT_DIR)build
BIN_DIR = $(BUILD_DIR)/bin
JSON_DIR = $(BUILD_DIR)/json

ifeq ($(OS),Windows_NT)
EXE_EXT = .exe
MKDIR_BUILD = if not exist "$(BUILD_DIR)" mkdir "$(BUILD_DIR)"
MKDIR_BIN = if not exist "$(BIN_DIR)" mkdir "$(BIN_DIR)"
MKDIR_JSON = if not exist "$(JSON_DIR)" mkdir "$(JSON_DIR)"
RUN_APP_CMD = "$(APP_BIN)"
RUN_TEST_CMD = "$(TEST_BIN)"
CLEAN_BINS = if exist "$(APP_BIN)" del /Q "$(APP_BIN)" & if exist "$(TEST_BIN)" del /Q "$(TEST_BIN)"
CLEAN_JSON = if exist "$(JSON_DIR)\*.json" del /Q "$(JSON_DIR)\*.json"
else
EXE_EXT =
MKDIR_BUILD = mkdir -p "$(BUILD_DIR)"
MKDIR_BIN = mkdir -p "$(BIN_DIR)"
MKDIR_JSON = mkdir -p "$(JSON_DIR)"
RUN_APP_CMD = "$(APP_BIN)"
RUN_TEST_CMD = "$(TEST_BIN)"
CLEAN_BINS = rm -f "$(APP_BIN)" "$(TEST_BIN)"
CLEAN_JSON = rm -f "$(JSON_DIR)"/*.json
endif

CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -I$(ROOT_DIR)lib -I$(ROOT_DIR)lib/Sha256 -I$(ROOT_DIR)src

APP_BIN = $(BIN_DIR)/blockchain$(EXE_EXT)
TEST_BIN = $(BIN_DIR)/autotest_runner$(EXE_EXT)

APP_SRC = $(ROOT_DIR)src/main.c $(ROOT_DIR)src/blockchain_app.c $(ROOT_DIR)src/blockchain_core.c $(ROOT_DIR)src/blockchain_state.c $(ROOT_DIR)src/blockchain_io.c $(ROOT_DIR)lib/Sha256/sha256.c $(ROOT_DIR)lib/Sha256/sha256_utils.c
TEST_SRC = $(ROOT_DIR)tests/autotest_main.c $(ROOT_DIR)tests/blockchain_test.c $(ROOT_DIR)src/blockchain_app.c $(ROOT_DIR)src/blockchain_core.c $(ROOT_DIR)src/blockchain_state.c $(ROOT_DIR)src/blockchain_io.c $(ROOT_DIR)lib/Sha256/sha256.c $(ROOT_DIR)lib/Sha256/sha256_utils.c

all: app test

dirs:
	$(MKDIR_BUILD)
	$(MKDIR_BIN)
	$(MKDIR_JSON)

app: dirs $(APP_BIN)

test: dirs $(TEST_BIN)

$(APP_BIN): $(APP_SRC)
	$(CC) $(CFLAGS) $(APP_SRC) -o $(APP_BIN)

$(TEST_BIN): $(TEST_SRC)
	$(CC) $(CFLAGS) $(TEST_SRC) -o $(TEST_BIN)

run-manual: app
	cd "$(ROOT_DIR)" && $(RUN_APP_CMD)

run-tests: test
	cd "$(ROOT_DIR)" && $(RUN_TEST_CMD)

clean:
	$(CLEAN_BINS)
	$(CLEAN_JSON)

.PHONY: all dirs app test run-manual run-tests clean