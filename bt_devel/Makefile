CC = gcc
CPFLAGS = -g -Wall
LDFLAGS = -lcrypto
LDLIBS = -lcurl


SRC = bencode.c  bt_client.c bt_lib.c bt_setup.c
OBJ = $(SRC:.c=.o)
BIN = bt_client.x86_64

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CPFLAGS) -o $(BIN) $(OBJ) $(LDFLAGS) $(LDLIBS)


%.o:%.c
	$(CC) -c $(CPFLAGS) -o $@ $<  

$(SRC):

clean:
	rm -rf $(OBJ) $(BIN)
