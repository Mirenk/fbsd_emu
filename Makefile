CFLAGS=-std=c11 -g -static
#SRCS=$(wildcard *.c)
SRCS=main.c
OBJS=$(SRCS:.c=.o)

predb: $(OBJS)
	$(CC) -o fbsd_emu $(OBJS) $(LDFLAGS)

clean:
	rm -f fbsd_emu *.o *~

.PHONY: clean

