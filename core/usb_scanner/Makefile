CC      := gcc
CFLAGS  := -Wall -Wextra -pthread
LDLIBS  := -ludev -lcrypto

# Fuentes que participan en el test:
SRCS := \
	scanner.c \
	report.c  \
	monitor.c \
	worker.c  \
	event_queue.c \
	legitimacy.c \
	scann.c\
	path_stat_table.c\
	monitor_utils.c

# Objetos derivados de las fuentes
OBJS := $(SRCS:.c=.o)

TARGET := scann

.PHONY: all clean

all: $(TARGET)

# Enlaza todos los objetos en el ejecutable
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# Regla genérica para compilar cada .c en .o
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
