CC      := gcc
CFLAGS  := -Wall -Wextra -O2 -std=c11
LDFLAGS := -liconv

TARGET  := evtx_decode
SRCS    := main.c hex_dump.c timestamp.c evtx_file.c evtx_chunk.c evtx_record.c evtx_binxml.c utf16le.c
OBJS    := $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c hex_dump.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)
