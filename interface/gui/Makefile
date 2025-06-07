.PHONY: all run clean

# Herramientas
CC      := gcc
PKG     := pkg-config

# Flags de compilación y enlace para GTK4
CFLAGS  := $(shell $(PKG) --cflags gtk4)
LIBS    := $(shell $(PKG) --libs   gtk4)

# Fuente y ejecutable
SRC     := src/main.c
EXEC    := gui-minimal

all: $(EXEC)

# Compilar main.c en un binario standalone
$(EXEC): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LIBS)

# Ejecutar directamente
run: $(EXEC)
	./$(EXEC)

clean:
	rm -f $(EXEC)
