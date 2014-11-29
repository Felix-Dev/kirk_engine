CC = gcc

CFLAGS = -Wall -g -O0 -I../kirk
LDFLAGS = -L../kirk -lrt -lkirk

all: decipl encipl

decipl: ipl_decrypt.o
	$(CC) -o $@ $^ $(LDFLAGS)
encipl: ipl_encrypt.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f decipl encipl ipl_decrypt.o ipl_encrypt.o
