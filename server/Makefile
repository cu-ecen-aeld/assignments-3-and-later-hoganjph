all: server

server: aesdserver.c
	@echo $(CC)
	$(CC) -Wall -Werror -o aesdsocket aesdserver.c

clean:
	rm -rf aesdsocket
