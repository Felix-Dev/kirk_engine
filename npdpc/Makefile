CC = gcc
CFLAGS = -Wall -fno-strict-aliasing -I../kirk -I../common
TARGET = npdpc
OBJS = main.o

ifeq ($(DEBUG), 1)
CFLAGS+=-g -O0
else
CFLAGS+=-O2
endif

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -L ../kirk -lkirk -lz

clean:
	rm -f $(OBJS) $(TARGET) $(TARGET).exe $(TARGET).exe.stackdump

