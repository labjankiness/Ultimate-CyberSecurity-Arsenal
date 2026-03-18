CC = gcc
CFLAGS = -Wall -Wextra -pthread -O2
TARGET = port_scanner

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c

clean:
	rm -f $(TARGET)
