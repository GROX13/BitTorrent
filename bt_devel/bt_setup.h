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

/**
* Initialise a bencode object.
* @param be The bencode object
* @param str Buffer we expect input from
* @param len Length of buffer
*/
void bencode_init(bencode_t *be, const char *str, int len);

/**
* @return 1 if the bencode object is an int; otherwise 0.
*/
int bencode_is_int(const bencode_t *be);

/**
* @return 1 if the bencode object is a string; otherwise 0.
*/
int bencode_is_string(const bencode_t *be);

/**
* @return 1 if the bencode object is a list; otherwise 0.
*/
int bencode_is_list(const bencode_t *be);

/**
* @return 1 if the bencode object is a dict; otherwise 0.
*/
int bencode_is_dict(const bencode_t *be);

/**
* Obtain value from integer bencode object.
* @param val Long int we are writing the result to
* @return 1 on success, otherwise 0
*/
int bencode_int_value(bencode_t *be, long int *val);

/**
* @return 1 if there is another item on this dict; otherwise 0.
*/
int bencode_dict_has_next(bencode_t *be);

/**
* Get the next item within this dictionary.
* @param be_item Next item.
* @param key Const pointer to key string of next item.
* @param klen Length of the key of next item.
* @return 1 on success; otherwise 0.
*/
int bencode_dict_get_next(bencode_t *be, bencode_t *be_item, const char **key, int *klen);

/**
* Get the string value from this bencode object.
* The buffer returned is stored on the stack.
* @param be The bencode object.
* @param str Const pointer to the buffer.
* @param slen Length of the buffer we are outputting.
* @return 1 on success; otherwise 0
*/
int bencode_string_value(bencode_t *be, const char **str, int *len);

/**
* Tell if there is another item within this list.
* @param be The bencode object
* @return 1 if another item exists on the list; 0 otherwise; -1 on invalid processing
*/
int bencode_list_has_next(bencode_t *be);

/**
* Get the next item within this list.
* @param be The bencode object
* @param be_item The next bencode object that we are going to initiate.
* @return return 0 on end; 1 on have next; -1 on error
*/
int bencode_list_get_next(bencode_t *be, bencode_t *be_item);

/**
* Copy bencode object into other bencode object
*/
void bencode_clone(bencode_t *be, bencode_t *output);

/**
* Get the start and end position of this dictionary
* @param be Bencode object
* @param start Starting string
* @param len Length of the dictionary
* @return 1 on success
*/
int bencode_dict_get_start_and_len(bencode_t *be, const char **start, int *len);

#endif
