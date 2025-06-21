# interface/gui/Makefile

CC       := gcc
PKG      := pkg-config

# Incluir headers de port-scanner, utils/port-scanner, monitor y usb_scanner
CORE_INC := -I../../core/port-scanner \
            -I../../utils/port-scanner \
            -I../../core/monitor \
            -I../../core/usb_scanner

# Flags de compilación: GTK4 + GLib/GThread + pthreads + includes
CFLAGS   := $(shell $(PKG) --cflags gtk4 gthread-2.0) -pthread $(CORE_INC)

# Flags de enlace: GTK4 + GLib/GThread + pthreads + libudev + libcrypto
LIBS     := $(shell $(PKG) --libs   gtk4 gthread-2.0) -pthread -ludev -lcrypto

# Tu librería estática de port-scanner
PORT_LIB := ../../core/port-scanner/libportscanner.a

# Fuente del monitor de procesos
MON_SRC  := ../../core/monitor/monitor.c

# Todos los .c de usb_scanner (incluye scann.c con scann_start/stop)
USB_SRCS := $(wildcard ../../core/usb_scanner/*.c)

# Código fuente de la GUI
SRC      := src/main.c

# Ejecutable resultante
EXEC     := gui-ports

.PHONY: all run clean

all: $(EXEC)

$(EXEC): $(SRC) $(PORT_LIB) $(MON_SRC) $(USB_SRCS)
	$(CC) $(CFLAGS) \
	    $(SRC) \
	    $(MON_SRC) \
	    $(USB_SRCS) \
	    $(PORT_LIB) \
	    -o $@ \
	    $(LIBS)

run: $(EXEC)
	./$(EXEC)

clean:
	rm -f $(EXEC)
