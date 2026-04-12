CC = gcc
LIBS = -lpcap
CFLAGS = -g -Wall -pedantic -std=gnu99

all:  trace 

trace: trace.c checksum.c
	$(CC) $(CFLAGS) -o $@ trace.c ethernet.c ip.c checksum.c printers.c $(LIBS)

clean:
	rm -f trace