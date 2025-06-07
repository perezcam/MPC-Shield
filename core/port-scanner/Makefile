# core/port-scanner/Makefile

CC      := gcc
AR      := ar rcs

# 1. Declaramos dónde están los headers de este módulo y de utils/port-scanner
CFLAGS  := -I. -I../../utils/port-scanner -pthread

# 2. Listado de fuentes: scanner.c (tu escáner) + scanner_utils.c (utilidades)
SRCS    := scanner.c \
           ../../utils/port-scanner/scanner_utils.c

# 3. Objs basados en los .c anteriores
OBJS    := scanner.o scanner_utils.o

# 4. Nombre de la librería que vamos a generar
LIB     := libportscanner.a

.PHONY: all clean

all: $(LIB)

# 5. Construir la librería a partir de los objetos
$(LIB): $(OBJS)
	$(AR) $@ $^

# 6. Reglas para compilar cada .o
scanner.o: scanner.c scanner.h
	$(CC) $(CFLAGS) -c $< -o $@

scanner_utils.o: ../../utils/port-scanner/scanner_utils.c \
                ../../utils/port-scanner/scanner_utils.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(LIB)
