CC = gcc
CFLAGS = -Wall -g -Iinclude -Wno-deprecated-declarations
LDFLAGS = -lssl -lcrypto
SRC_DIR = src
BIN_DIR = bin
TARGET = $ bin/protocol

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean