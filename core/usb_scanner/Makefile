# Makefile for usb_scanner project

CC      := gcc
CFLAGS  := -Wall -Wextra  -pthread
LDLIBS  := -ludev

SRCS    := scanner.c report.c scanner_test.c
TARGET  := scanner_test

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET) *.o
