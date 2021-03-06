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
* handshake(peer_t *peer, bt_handshake_t msg) -> int
*
* sends handshake message to given peer
*
* ERRORS: Will exit on various errors
*/
int handshake(peer_t *peer, bt_handshake_t msg);

/**
* create_file(bt_args_t *bt_args, char *filename, char* file_type) -> FILE *
*
*
*
* ERRORS: Will exit on various errors
*
**/

FILE *create_file(bt_args_t *bt_args, char *filename, char* file_type);

/**
* ERRORS: Will exit on various errors
*/
char *generate_peer_id();

/**
* ERRORS: Will exit on various errors
*/
char *url_encode(char *str);

/**
* ERRORS: Will exit on various errors
*/
char *url_decode(char *str);

/**
* ERRORS: Will exit on various errors
*/
int print_bytes(void * buff);

/**
* ERRORS: Will exit on various errors
*/
char *byte_to_binary(int x);

int piece_is_in_bitfield(int piece_index, bt_bitfield_t* bitfield_t);

int put_piece_in_bitfield(int piece_index, bt_bitfield_t* bitfield_t);

int find_log_file(bt_args_t *bt_args);

#endif
