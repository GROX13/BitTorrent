#ifndef _BT_SETUP_H
#define _BT_SETUP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "bt_setup.h"
#include "bt_lib.h"
#include "bencode.h"


typedef struct bt_peer{
    char tracker_id[FILE_NAME_MAX]; 
    int complete; 
    int incomplete; 
    int interval; 
    char peer_hashes[1024]; 
} bt_peer;

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

int create_socket(char *ip_addr, unsigned short port);

char *generate_peer_id();

char *url_encode(char *str);

char *url_decode(char *str);

void decode_tracker_info(char *info);

#endif
