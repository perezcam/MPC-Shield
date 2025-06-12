# interface/gui/Makefile

CC       := gcc
PKG      := pkg-config

# Incluir headers de core y de utils/port-scanner (models.h)
CORE_INC := -I../../core/port-scanner \
            -I../../utils/port-scanner

# Flags de compilación: GTK4 + pthreads + rutas de include
CFLAGS   := $(shell $(PKG) --cflags gtk4) -pthread $(CORE_INC)

# Flags de enlace: GTK4 + pthreads
LIBS     := $(shell $(PKG) --libs   gtk4) -pthread

# Librería estática del core
CORE_LIB := ../../core/port-scanner/libportscanner.a

SRC      := src/main.c
EXEC     := gui-ports

.PHONY: all run clean

all: $(EXEC)

$(EXEC): $(SRC) $(CORE_LIB)
	$(CC) $(CFLAGS) $< -o $@ $(LIBS) $(CORE_LIB)

run: $(EXEC)
	./$(EXEC)

clean:
	rm -f $(EXEC)
