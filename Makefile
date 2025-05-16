CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -Iutils/port-scanner
SRC = core/port-scanner/scanner.c utils/port-scanner/scanner_utils.c
BIN = bin/port-scanner

$(BIN): $(SRC)
	mkdir -p bin
	$(CC) $(CFLAGS) -o $(BIN) $(SRC)

clean:
	rm -rf bin
