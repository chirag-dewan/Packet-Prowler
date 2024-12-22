CC = gcc
CFLAGS = -Wall -Wextra

SRC = src/main.c src/packet_sniffer.c src/utils.c
OBJ = $(SRC:.c=.o)

EXEC = PacketProwler

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f $(OBJ) $(EXEC)

