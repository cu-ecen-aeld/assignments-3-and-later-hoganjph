CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -Werror
TARGET ?= aesdsocket
LDFLAGS ?= -pthread -lrt

all: server

server: aesdserver.c
	@echo $(CC) $(CFLAGS) $^ -o $(TARGET) $(INCLUDES) $(LDFLAGS)
	$(CC) $(CFLAGS) $^ -o $(TARGET) $(INCLUDES) $(LDFLAGS)

clean:
	rm -rf aesdsocket
