# Makefile para compilar el test de detección (scanner_test)
# Incluye enlace con libcrypto (para SHA256) y libudev

CC      := gcc
CFLAGS  := -Wall -Wextra -pthread
LDLIBS  := -ludev -lcrypto

# Fuentes que participan en el test:
#  - scanner.c       (scanner_thread, mark_mount, get_current_mounts, ...)
#  - report.c        (report_current_mounts, report_file_modification, get_path_from_fd, …)
#  - monitor.c       (monitor_thread, hace push_event y get_path_from_fd)
#  - worker.c        (worker_thread, push_event, pop_event, sha256_file)
#  - event_queue.c   (implementación de push_event/pop_event)
#  - shared.c        (definición de g_fan_content_fd y g_fan_notify_fd)
#  - scanner_test.c  (main() de prueba)

SRCS := \
	scanner.c \
	report.c  \
	monitor.c \
	worker.c  \
	event_queue.c \
	shared.c  \
	scanner_test.c

TARGET := scanner_test

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET) *.o
