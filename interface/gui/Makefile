# interface/gui/Makefile

CC       := gcc
PKG      := pkg-config

# Incluir headers de port-scanner, utils/port-scanner y monitor
CORE_INC := -I../../core/port-scanner \
            -I../../utils/port-scanner \
            -I../../core/monitor

# Flags de compilación: GTK4 + pthreads + includes
CFLAGS   := $(shell $(PKG) --cflags gtk4) -pthread $(CORE_INC)

# Flags de enlace: GTK4 + pthreads
LIBS     := $(shell $(PKG) --libs   gtk4) -pthread

# Tu librería estática de port-scanner
PORT_LIB := ../../core/port-scanner/libportscanner.a

# Origen de monitor (lo compilamos en línea)
MON_SRC  := ../../core/monitor/monitor.c

# Código fuente de la GUI
SRC      := src/main.c

# Ejecutable
EXEC     := gui-ports

.PHONY: all run clean

all: $(EXEC)

$(EXEC): $(SRC) $(PORT_LIB) $(MON_SRC)
	$(CC) $(CFLAGS) $(SRC) $(MON_SRC) $(PORT_LIB) -o $@ $(LIBS)

run: $(EXEC)
	./$(EXEC)

clean:
	rm -f $(EXEC)
