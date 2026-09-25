CC ?= gcc
CFLAGS ?= -O3 -Wall -Wextra -std=c99
TARGET = bin/sentineld

all: $(TARGET)

$(TARGET): src/sentineld.c
	mkdir -p bin
	$(CC) $(CFLAGS) src/sentineld.c -o $(TARGET)

clean:
	rm -rf bin

test: $(TARGET)
	./$(TARGET) --self-test

.PHONY: all clean test
