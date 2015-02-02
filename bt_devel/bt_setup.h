#ifndef _BT_SETUP_H
#define _BT_SETUP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

#include "bt_setup.h"
#include "bt_lib.h"
#include "bencode.h"


typedef struct bt_peer {
    char tracker_id[FILE_NAME_MAX];
    int complete;
    int incomplete;
    int interval;
    char peer_hashes[1024];
} bt_peer;

typedef struct {
    const char *str;
    const char *start;
    void *parent;
    int val;
    int len;
} bencode_t;

typedef struct
{
    uint8_t protocol_name_length;
    char protocol_name[19];
    char reserved_bytes[8];
    char hash_info[20];
    char peer_id[20];
} bt_handshake_t;

/**
* __parse_peer(peer_t * peer, char peer_st) -> void
*
* parse a peer string, peer_st and store the parsed result in peer
*
* ERRORS: Will exit on various errors
**/
void usage(FILE *file);


/**
* pars_args(bt_args_t * bt_args, int argc, char * argv[]) -> void
*
* parse the command line arguments to bt_client using getopt and
* store the result in bt_args.
*
* ERRORS: Will exit on various errors
*
**/

void parse_args(bt_args_t *bt_args, int argc, char **argv);

/**
* read_file(char *file, long long *len) -> char *
*
* parse the torrent file and return it's
* representation as a char array.
*
* ERRORS: Will exit on various errors
*
**/
char *read_file(char *file, long long *len);

int create_socket(char *ip_addr, unsigned short port);

char *generate_peer_id();

char *url_encode(char *str);

char *url_decode(char *str);

void decode_tracker_info(bt_args_t *bt_args, char *info);

int handshake(peer_t *peer, bt_handshake_t msg);

#endif
