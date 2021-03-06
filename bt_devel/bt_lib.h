#ifndef _BT_LIB_H
#define _BT_LIB_H

//standard stuff
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <poll.h>

//networking stuff
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <netdb.h>

#include "bt_lib.h"
#include "bencode.h"
#include "bt_io.h"

/*Maximum file name size, to make things easy*/
#define FILE_NAME_MAX 1024

/*Maxium number of connections*/
#define MAX_CONNECTIONS 2048

/*initial port to try and open a listen socket on*/
#define INIT_PORT 6881

/*max port to try and open a listen socket on*/
#define MAX_PORT 6889

/*Different BitTorrent Message Types*/
#define BT_CHOKE 0
#define BT_UNCHOKE 1
#define BT_INTERSTED 2
#define BT_NOT_INTERESTED 3
#define BT_HAVE 4
#define BT_BITFILED 5
#define BT_REQUEST 6
#define BT_PIECE 7
#define BT_CANCEL 8

/*size (in bytes) of id field for peers*/
#define ID_SIZE 20

/*size (in bytes) of some info fields*/
#define BT_PEER_SIZE 64
#define BT_INFO_HASH_SIZE 64
#define FILE_LENGTH_MAX 16384


typedef enum
{
    BT_KEEP_ALIVE_T,
    BT_BITFIELD_T,
    BT_REQUEST_T,
    BT_CANCEL_T,
    BT_PIECE_T,
    BT_INTERESTED_T,
    BT_CHOKE_T,
    BT_UNCHOKE_T,
    BT_NOT_INTERESTED_T,
    BT_HAVE_T,
} bt_msg_type;

//holds information about a peer
typedef struct peer
{
    unsigned char id[ID_SIZE]; //the peer id
    unsigned short port; //the port to connect n
    struct sockaddr_in sockaddr; //sockaddr for peer
    int socket_fd; //socket connection to this peer
    int choked; //peer choked?
    int interested; //peer interested?
} peer_t;

typedef struct bt_peer {
    char tracker_id[FILE_NAME_MAX];
    int complete;
    int incomplete;
    int interval;
    char peer_hashes[1024];
} bt_peer;

//holds information about a torrent file
typedef struct
{
    char announce[FILE_NAME_MAX]; //url of tracker
    char name[FILE_NAME_MAX]; //name of file
    int piece_length; //number of bytes in each piece
    int length; //length of the file in bytes
    int num_pieces; //number of pieces, computed based on above two values
    char **piece_hashes; //pointer to 20 byte data buffers containing the sha1sum of each of the pieces
} bt_info_t;


/**
* Message structures
**/

typedef struct
{
    char *bitfield; //bitfield where each bit represents a piece that
    //the peer has or doesn't have
    size_t size;//size of the bitfiled
} bt_bitfield_t;

typedef struct
{
    uint32_t index; //which piece index
    uint32_t begin; //offset within piece
    uint32_t length; //amount wanted, within a power of two
} bt_request_t;

typedef struct
{
    uint32_t index; //which piece index
    uint32_t begin; //offset within piece
    char *piece; //pointer to start of the data for a piece
    size_t size;//size of the piece
} bt_piece_t;


typedef struct bt_msg
{
    uint32_t length; //length of remaining message,
    //0 length message is a keep-alive message
    //unsigned char bt_type; type of bt_mesage

    bt_msg_type type;//type of bt_mesage

    //payload can be any of these
    union
    {
        bt_bitfield_t bitfiled;
        //send a bitfield
        uint32_t have; //what piece you have
        bt_piece_t piece; //a peice message
        bt_request_t request; //request messge
        bt_request_t cancel; //cancel message, same type as request
        char data[0];//pointer to start of payload, just incase
    } payload;

} bt_msg_t;


//holds all the agurments and state for a running the bt client
typedef struct
{
    int verbose; //verbose level
    //the filename to save to
    char save_file[FILE_NAME_MAX];
    //the file to save to
    FILE *f_save;
    //the log file
    char log_file[FILE_NAME_MAX];
    // *.torrent file
    char torrent_file[FILE_NAME_MAX];
    //my peer id
    char bt_peer_id[BT_PEER_SIZE];
    //info sha1 hash
    char info_hash[BT_INFO_HASH_SIZE];

    peer_t *peers[MAX_CONNECTIONS]; // array of peer_t pointers
    unsigned int id; //this bt_clients id
    int sockets[MAX_CONNECTIONS]; //Array of possible sockets
    int epollfd; //epoll file descriptor
    struct epoll_event poll_sockets[MAX_CONNECTIONS]; //Arry of pollfd for polling for input

    /*set once torrent is parse*/
    bt_info_t *bt_info; //the parsed info for this torrent
    bt_bitfield_t bitfield; //my bitfield which pieces i have
} bt_args_t;


int parse_bt_info(bt_info_t *bt_info, be_node *node);

/*choose a random id for this node*/
unsigned int select_id();

/*propogate a peer_t struct and add it to the bt_args structure*/
int add_peer(peer_t *peer, bt_args_t *bt_args, char *hostname, unsigned short port);

/*drop an unresponsive or failed peer from the bt_args*/
int drop_peer(peer_t *peer, bt_args_t *bt_args);

/* initialize connection with peers */
int init_peer(peer_t *peer, char *id, char *ip, unsigned short port);


/*calc the peer id based on the string representation of the ip and
  port*/
void calc_id(char *ip, unsigned short port, char *id);

/* print info about this peer */
void print_peer(peer_t *peer);

/* check status on peers, maybe they went offline? */
int check_peer(peer_t *peer);

/*check if peers want to send me something*/
int poll_peers(bt_args_t *bt_args);

/*send a msg to a peer*/
int send_to_peer(peer_t *peer, bt_msg_t *msg);

/*read a msg from a peer and store it in msg*/
int read_from_peer(peer_t *peer, bt_msg_t *msg);


/* save a piece of the file */
int save_piece(bt_args_t *bt_args, bt_piece_t *piece_t);

/*load a piece of the file into piece */
int load_piece(bt_args_t *bt_args, bt_piece_t *piece_t);

/*load the bitfield into bitfield*/
int get_bitfield(bt_args_t *bt_args, bt_bitfield_t *bitfield);

/*compute the sha1sum for a piece, store result in hash*/
int sha1_piece(bt_args_t *bt_args, bt_piece_t *piece, unsigned char *hash);


/*Contact the tracker and update bt_args with info learned,
  such as peer list*/
int contact_tracker(bt_args_t *bt_args);


#endif
