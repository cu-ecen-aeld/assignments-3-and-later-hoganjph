all: writer

writer.o: writer.c
	@echo $(CC)
	$(CC) $(CCFLAGS) -c writer.c

writer: writer.o
	$(CC) $(LDFLAGS) writer.o -o writer

.PHONY : clean
clean :
	rm -fr writer

