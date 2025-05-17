# Makefile para MPC-Shield con soporte a Glib

CC         := gcc

# Flags de Glib
PKG_CFLAGS := $(shell pkg-config --cflags glib-2.0)
PKG_LIBS   := $(shell pkg-config --libs   glib-2.0)

# Include paths: proyecto + Glib
INCLUDES   := -I. -Icore/monitor -Iinterface -Iutils $(PKG_CFLAGS)

# Flags de compilación y enlace
CFLAGS     := -Wall -Wextra -g $(INCLUDES)
LDFLAGS    := $(PKG_LIBS)

# Todas las fuentes .c (incluye interface/main.c)
SRCS       := $(wildcard core/monitor/*.c) \
              $(wildcard interface/*.c)     \
              $(wildcard utils/*.c)
OBJS       := $(SRCS:.c=.o)

TARGET     := mpc_shield

.PHONY: all clean run

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@

# Regla genérica: .c → .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: all
	./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
