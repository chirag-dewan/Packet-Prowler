CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lpcap

SRC = src/main.c src/packet_sniffer.c src/utils.c
OBJ = $(SRC:.c=.o)

EXEC = PacketProwler

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJ) $(EXEC)

