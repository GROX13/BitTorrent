CC = gcc
CPFLAGS = -g -Wall
LDFLAGS = -lcrypto -lcurl -lpthread


SRC = bencode.c bt_client.c bt_lib.c bt_setup.c bt_sock.c
OBJ = $(SRC:.c=.o)
BIN = bt_client.x86_64

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) -o $(BIN) $(OBJ) $(LDFLAGS)


%.o:%.c
	$(CC) -c $(CPFLAGS) -o $@ $<  

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)
