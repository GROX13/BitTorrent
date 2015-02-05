#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <glob.h>
#include <assert.h>
#include <inttypes.h>

#include "bt_setup.h"
#include "bt_lib.h"
#include "bencode.h"

// Symbols of length 20
#define CONS_RAND "RRRRRRRRRRRRRRRRRRRR"

/**
* usage(FILE * file) -> void
*
* print the usage of this program to the file stream file
*
**/

void usage(FILE *file)
{
    if (file == NULL)
    {
        file = stdout;
    }

    fprintf(file,
            "bt-client [OPTIONS] file.torrent\n"
            "  -h            \t Print this help screen\n"
            "  -b ip         \t Bind to this ip for incoming connections, ports\n"
            "                \t are selected automatically\n"
            "  -s save_file  \t Save the torrent in directory save_dir (dflt: .)\n"
            "  -l log_file   \t Save logs to log_filw (dflt: bt-client.log)\n"
            "  -p ip:port    \t Instead of contacing the tracker for a peer list,\n"
            "                \t use this peer instead, ip:port (ip or hostname)\n"
            "                \t (include multiple -p for more than 1 peer)\n"
            "  -I id         \t Set the node identifier to id (dflt: random)\n"
            "  -v            \t verbose, print additional verbose info\n");
}

/**
* __parse_peer(peer_t * peer, char peer_st) -> void
*
* parse a peer string, peer_st and store the parsed result in peer
*
* ERRORS: Will exit on various errors
**/

void __parse_peer(peer_t *peer, char *peer_st)
{
    char *parse_str;
    char *word;
    unsigned short port;
    char *ip;
    char id[20];
    char sep[] = ":";
    int i;

    //need to copy becaus strtok mangels things
    parse_str = malloc(strlen(peer_st) + 1);
    strncpy(parse_str, peer_st, strlen(peer_st) + 1);

    //only can have 2 tokens max, but may have less
    for (word = strtok(parse_str, sep), i = 0;
            (word && i < 3);
            word = strtok(NULL, sep), i++)
    {

        printf("%d:%s\n", i, word);
        switch (i)
        {
        case 0://id
            ip = word;
            break;
        case 1://ip
            port = atoi(word);
        default:
            break;
        }

    }

    if (i < 2)
    {
        fprintf(stderr, "ERROR: Parsing Peer: Not enough values in '%s'\n", peer_st);
        usage(stderr);
        exit(1);
    }

    if (word)
    {
        fprintf(stderr, "ERROR: Parsing Peer: Too many values in '%s'\n", peer_st);
        usage(stderr);
        exit(1);
    }


    //calculate the id, value placed in id
    calc_id(ip, port, id);

    //build the object we need
    init_peer(peer, id, ip, port);

    //free extra memory
    free(parse_str);

    return;
}

/**
* pars_args(bt_args_t * bt_args, int argc, char * argv[]) -> void
*
* parse the command line arguments to bt_client using getopt and
* store the result in bt_args.
*
* ERRORS: Will exit on various errors
*
**/
void parse_args(bt_args_t *bt_args, int argc, char *argv[])
{
    int ch; //ch for each flag
    int n_peers = 0;
    int i;

    /* set the default args */
    bt_args->verbose = 0; //no verbosity

    //null save_file, log_file and torrent_file
    memset(bt_args->save_file, 0x00, FILE_NAME_MAX);
    memset(bt_args->torrent_file, 0x00, FILE_NAME_MAX);
    memset(bt_args->log_file, 0x00, FILE_NAME_MAX);

    //null out file pointers
    bt_args->f_save = NULL;

    //null bt_info pointer, should be set once torrent file is read
    bt_args->bt_info = NULL;

    //default lag file
    strncpy(bt_args->log_file, "bt-client.log", FILE_NAME_MAX);

    for (i = 0; i < MAX_CONNECTIONS; i++)
    {
        bt_args->peers[i] = NULL; //initially NULL
    }

    bt_args->id = 0;

    while ((ch = getopt(argc, argv, "hp:s:l:vI:")) != -1)
    {
        switch (ch)
        {
        case 'h': //help
            usage(stdout);
            exit(0);
            break;
        case 'v': //verbose
            bt_args->verbose = 1;
            break;
        case 's': //save file
            strncpy(bt_args->save_file, optarg, FILE_NAME_MAX);
            break;
        case 'l': //log file
            strncpy(bt_args->log_file, optarg, FILE_NAME_MAX);
            break;
        case 'p': //peer
            n_peers++;
            //check if we are going to overflow
            if (n_peers > MAX_CONNECTIONS)
            {
                fprintf(stderr, "ERROR: Can only support %d initial peers", MAX_CONNECTIONS);
                usage(stderr);
                exit(1);
            }

            bt_args->peers[n_peers] = malloc(sizeof(peer_t));

            //parse peers
            __parse_peer(bt_args->peers[n_peers], optarg);
            break;
        case 'I':
            bt_args->id = (unsigned int) atoi(optarg);
            break;
        default:
            fprintf(stderr, "ERROR: Unknown option '-%c'\n", ch);
            usage(stdout);
            exit(1);
        }
    }


    argc -= optind;
    argv += optind;

    if (argc == 0)
    {
        fprintf(stderr, "ERROR: Require torrent file\n");
        usage(stderr);
        exit(1);
    }

    //copy torrent file over
    strncpy(bt_args->torrent_file, argv[0], FILE_NAME_MAX);

    return;
}

void _remove_char(char *str, char garbage)
{

    char *src, *dst;
    for (src = dst = str; *src != '\0'; src++)
    {
        *dst = *src;
        if (*dst != garbage) dst++;
    }
    *dst = '\0';
}

char *generate_peer_id()
{
    time_t current_time;
    char *c_time_string;

    current_time = time(NULL);
    //current time
    if (current_time == ((time_t) - 1))
        (void) fprintf(stderr, "Failure to compute.");

    c_time_string = ctime(&current_time);

    if (c_time_string == NULL)
        (void) fprintf(stderr, "Failure to convert.");

    _remove_char(c_time_string, ' ');
    _remove_char(c_time_string, ':');

    char *result = malloc(21);
    memset(result, '\0', 21);
    memcpy(result, CONS_RAND, 20);

    memcpy(result, c_time_string, strlen(c_time_string) - 1);

    return result;

}

/* Converts a hex character to its integer value */
char from_hex(char ch)
{
    return (char) (isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10);
}

/* Converts an integer value to its hex character*/
char to_hex(char code)
{
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(char *str)
{
    char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
    while (*pstr)
    {
        if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
            *pbuf++ = *pstr;
        else if (*pstr == ' ')
            *pbuf++ = '+';
        else
            *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex((char) (*pstr & 15));
        pstr++;
    }
    *pbuf = '\0';
    return buf;
}

/* Returns a url-decoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_decode(char *str)
{
    char *pstr = str, *buf = malloc(strlen(str) + 1), *pbuf = buf;
    while (*pstr)
    {
        if (*pstr == '%')
        {
            if (pstr[1] && pstr[2])
            {
                *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
                pstr += 2;
            }
        }
        else if (*pstr == '+')
        {
            *pbuf++ = ' ';
        }
        else
        {
            *pbuf++ = *pstr;
        }
        pstr++;
    }
    *pbuf = '\0';
    return buf;
}

int handshake(peer_t *peer, bt_handshake_t msg)
{
    int sockfd = peer->socket_fd;

    // datashi structuris gadawera

    char data[68];
    int size = sizeof(msg.protocol_name_length);
    int offset = 0;
    memcpy(&data[offset], &msg.protocol_name_length, (size_t) size);
    offset = offset + size;
    size =  sizeof(msg.protocol_name);
    memcpy(&data[offset], msg.protocol_name, (size_t) size);

    offset = offset + size;
    size = sizeof(msg.reserved_bytes);
    memcpy(&data[offset], msg.reserved_bytes, (size_t) size);

    offset = offset + size;
    size = sizeof(msg.hash_info);
    memcpy(&data[offset], msg.hash_info, (size_t) size);

    offset = offset + size;
    size = sizeof(msg.peer_id);
    memcpy(&data[offset], msg.peer_id, (size_t) size);

    size = (int) write(sockfd, data, sizeof(bt_handshake_t));

//    char buff[68];
//    memset(buff, '\0', 68);
//    size = (int) read(sockfd, buff, 68);
//    printf("received size: %i\nreceived %s\n", size, buff);
//
//    if (size == 68){
//        memcpy(&peer->id, &buff[48], 20);
//        printf("PEER ID IS: %s\n", peer->id);
//    }
//    bt_msg_t *msg1 = malloc(sizeof(bt_msg_t));
//    read_from_peer(peer, msg1);
//    int msg_len = 0;
//    size = (int) read(sockfd, &msg_len, sizeof(int));
//    msg_len = ntohl(msg_len);
//    printf("Message length is: %i\n", msg_len);
//
//
//    uint8_t msg_id;
//    size = (int) read(sockfd, &msg_id, sizeof(char));
//    printf("Message id is:  %" SCNd8 "\n", msg_id);
//
//    switch (msg_id)
//    {
//
//    case BT_CHOKE:
//        peer->choked = 0;
//        break;
//
//    case BT_UNCHOKE:
//        peer->choked = 1;
//        break;
//
//    case BT_INTERSTED:
//        peer->interested = 0;
//        break;
//    case BT_NOT_INTERESTED:
//        peer->interested = 1;
//        break;
//
//    case BT_HAVE:
//
//        break;
//
//    case BT_BITFILED:;
//        bt_bitfield_t *bt_bitfield = malloc(sizeof(bt_bitfield_t));
//        bt_bitfield->size = (size_t)(msg_len - 1);
//        printf("bitfield size is : %zu\n", bt_bitfield->size);
//        bt_bitfield->bitfield = malloc(bt_bitfield->size);
//        size = (int) read(sockfd, bt_bitfield->bitfield, bt_bitfield->size);
//        printf("bitfield size is : %zu\n", size);
//        //size = (int) read(sockfd, bt_bitfield->bitfield, bt_bitfield->size);
//        break;
//
//    case BT_REQUEST:;
//        bt_request_t *bt_request = malloc(sizeof(bt_request_t));
//        size = (int) read(sockfd, &bt_request->index, sizeof(int));
//        size = (int) read(sockfd, &bt_request->begin, sizeof(int));
//        size = (int) read(sockfd, &bt_request->length, sizeof(int));
//        break;
//
//    case BT_PIECE:;
//        bt_piece_t *bt_piece = malloc(sizeof(bt_piece_t));
//        int block_len = msg_len - 9;
//        size = (int) read(sockfd, &bt_piece->index, sizeof(int));
//        size = (int) read(sockfd, &bt_piece->begin, sizeof(int));
//        size = (int) read(sockfd, &bt_piece->piece, block_len);
//        break;
//
//    case BT_CANCEL:
//
//        break;
//
//    default:
//        break;
//    }

    return size;
}

int print_bytes(void *buff)
{
    size_t i;
    printf("[");
    for (i = 0; i < 17; ++i)
        printf("%02X", ((unsigned char *)buff)[i]);
    printf("]\n");
    return 0;
}

char *byte_to_binary(int x)
{
    static char b[9];
    b[0] = '\0';

    int z;
    for (z = 128; z > 0; z >>= 1)
    {
        strcat(b, ((x & z) == z) ? "1" : "0");
    }

    return b;
}

FILE *create_file(bt_args_t *bt_args, char *filename, char *file_type)
{
    FILE *fp = fopen(filename, file_type);
    memcpy(&bt_args->save_file, filename, strlen(filename));
    bt_args->f_save = fp;
    return fp;
}

uint8_t power_of_num(int base, int exp){
    uint8_t value=1;
    while (exp!=0){
        value*=base;  
        --exp;
    }
    return value;
}

int piece_is_in_bitfield(int piece_index, bt_bitfield_t* bitfield_t){
    char* bits = malloc(sizeof(bitfield_t->bitfield));
    size_t size = sizeof(bitfield_t->bitfield);
    memcpy(bits, bitfield_t->bitfield, size);
    long num_of_pieces = sizeof(bitfield_t->bitfield) * 8;

    if(piece_index >= num_of_pieces) return 1;
    
    int byte_index = piece_index/8;
    
    int bit_index = piece_index%8;

    uint8_t num = power_of_num(2, bit_index);

    uint8_t get_byte = 0;
    
    memcpy(&get_byte, (char*)bits + byte_index, sizeof(char));

    if((get_byte&num) != num) return 1;
   
    return 0;
}

int put_piece_is_in_bitfield(int piece_index, bt_bitfield_t* bitfield_t){
    
    if(piece_is_in_bitfield(piece_index, bitfield_t) == 0) return 1;
    
    int byte_index = piece_index/8;
    
    int bit_index = piece_index%8;

    uint8_t get_byte = 0;
    
    memcpy(&get_byte, (char*)bitfield_t->bitfield + byte_index, sizeof(char));
        
    uint8_t num = power_of_num(2, bit_index);
   
    get_byte = get_byte|num;

    memcpy((char*)bitfield_t->bitfield + byte_index, &get_byte, sizeof(char));
                
    return 0;
}















