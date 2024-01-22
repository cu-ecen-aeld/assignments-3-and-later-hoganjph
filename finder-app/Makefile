ifneq ($(CROSS_COMPILE),)
CC:=$(CROSS_COMPILE)gcc
else
CC=gcc
endif

writer :
	@echo $(CC)
	$(CC) -Wall -Werror -o writer writer.c

.PHONY : clean
clean :
	rm -fr writer
    
