CC = gcc
CPFLAGS = -g -Wall
LDFLAGS = -lcrypto

SRC = bt_client.c setup.c bt_bencode.c
OBJ = $(SRC:.c=.o)
BIN = bt_client

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) -o $(BIN) $(OBJ) $(LDFLAGS) 


%.o:%.c
	$(CC) -c $(CPFLAGS) -o $@ $<  

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)
