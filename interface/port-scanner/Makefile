# -----------------------------------------
# Makefile para interface/port-scanner
# -----------------------------------------
CC             := gcc
CFLAGS         := -Wall -Wextra \
                  -I../../core/port-scanner \
                  -I../../utils/port-scanner \
                  -pthread
CFLAGS_TEST    := $(CFLAGS) -DTEST

BIN_DIR        := bin
TARGET         := $(BIN_DIR)/port-scanner

# Para los tests
TEST_SRC       := ../../tests/test_port-scanner.c
TEST_UTILS_FAKE:= ../../utils/port-scanner/test_scanner_utils.c
TEST_BIN       := $(BIN_DIR)/test_port-scanner

.PHONY: all test clean

all: $(TARGET)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Compila el ejecutable principal
$(TARGET): | $(BIN_DIR)
	$(CC) $(CFLAGS) \
	    main.c \
	    ../../core/port-scanner/scanner.c \
	    ../../utils/port-scanner/scanner_utils.c \
	    -o $(TARGET)

# Compila y ejecuta el test (usa la versión TEST de scanner_utils)
test: $(TEST_BIN)
	@echo "=== Ejecutando test_port-scanner ==="
	./$(TEST_BIN)

$(TEST_BIN): | $(BIN_DIR)
	$(CC) $(CFLAGS_TEST) \
	    ../../core/port-scanner/scanner.c \
	    ../../utils/port-scanner/scanner_utils.c \
	    $(TEST_UTILS_FAKE) \
	    $(TEST_SRC) \
	    -o $(TEST_BIN)

# Limpia binarios
clean:
	rm -rf $(BIN_DIR)
