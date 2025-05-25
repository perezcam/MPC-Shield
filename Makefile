#Compile and test with:
#make clean
#make 
#make test


CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Iutils/port-scanner
SRC = core/port-scanner/scanner.c utils/port-scanner/scanner_utils.c
BIN = bin/port-scanner
TEST_SRC = tests/test_port-scanner.c utils/port-scanner/test_scanner_utils.c
TEST_BIN = tests/test_scanner

# Compila el ejecutable principal
$(BIN): $(SRC)
	mkdir -p bin
	$(CC) $(CFLAGS) -o $(BIN) $(SRC)

# Compila el test (sin ejecutarlo)
$(TEST_BIN): $(TEST_SRC)
	$(CC) $(CFLAGS) -o $(TEST_BIN) $(TEST_SRC)

# Ejecuta el test con sudo (porque abre puertos <1024) (necesita contraseña)
test: $(TEST_BIN) $(BIN)
	sudo $(TEST_BIN)

# Limpia binarios
clean:
	rm -rf bin $(TEST_BIN)







