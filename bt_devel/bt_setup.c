#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <glob.h>
#include <assert.h>


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

void usage(FILE *file) {
    if (file == NULL) {
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

void __parse_peer(peer_t *peer, char *peer_st) {
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
         word = strtok(NULL, sep), i++) {

        printf("%d:%s\n", i, word);
        switch (i) {
            case 0://id
                ip = word;
                break;
            case 1://ip
                port = atoi(word);
            default:
                break;
        }

    }

    if (i < 2) {
        fprintf(stderr, "ERROR: Parsing Peer: Not enough values in '%s'\n", peer_st);
        usage(stderr);
        exit(1);
    }

    if (word) {
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
void parse_args(bt_args_t *bt_args, int argc, char *argv[]) {
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

    for (i = 0; i < MAX_CONNECTIONS; i++) {
        bt_args->peers[i] = NULL; //initially NULL
    }

    bt_args->id = 0;

    while ((ch = getopt(argc, argv, "hp:s:l:vI:")) != -1) {
        switch (ch) {
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
                if (n_peers > MAX_CONNECTIONS) {
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

    if (argc == 0) {
        fprintf(stderr, "ERROR: Require torrent file\n");
        usage(stderr);
        exit(1);
    }

    //copy torrent file over
    strncpy(bt_args->torrent_file, argv[0], FILE_NAME_MAX);

    return;
}

/**
*
* */
int create_socket(char *ip_addr, unsigned short port) {
    int socket_desc;
    struct sockaddr_in server;

    //Create socket
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        printf("Could not create socket");
    }

    server.sin_addr.s_addr = inet_addr(ip_addr);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    //Connect to remote server
    if (connect(socket_desc, (struct sockaddr *) &server, sizeof(server)) < 0) {
        puts("connect error");
        return 1;
    }
    puts("Connected");

    return socket_desc;
}

void _remove_char(char *str, char garbage) {

    char *src, *dst;
    for (src = dst = str; *src != '\0'; src++) {
        *dst = *src;
        if (*dst != garbage) dst++;
    }
    *dst = '\0';
}

char *generate_peer_id() {
    time_t current_time;
    char *c_time_string;

    current_time = time(NULL);

    if (current_time == ((time_t) -1))
        (void) fprintf(stderr, "Failure to compute the current time.");

    c_time_string = ctime(&current_time);

    if (c_time_string == NULL)
        (void) fprintf(stderr, "Failure to convert the current time.");

    _remove_char(c_time_string, ' ');
    _remove_char(c_time_string, ':');

    char *result = malloc(21);
    memset(result, '\0', 21);
    memcpy(result, CONS_RAND, 20);

    memcpy(result, c_time_string, strlen(c_time_string) - 1);

    return result;

}

/* Converts a hex character to its integer value */
char from_hex(char ch) {
    return (char) (isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10);
}

/* Converts an integer value to its hex character*/
char to_hex(char code) {
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_encode(char *str) {
    char *pstr = str, *buf = malloc(strlen(str) * 3 + 1), *pbuf = buf;
    while (*pstr) {
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
char *url_decode(char *str) {
    char *pstr = str, *buf = malloc(strlen(str) + 1), *pbuf = buf;
    while (*pstr) {
        if (*pstr == '%') {
            if (pstr[1] && pstr[2]) {
                *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
                pstr += 2;
            }
        } else if (*pstr == '+') {
            *pbuf++ = ' ';
        } else {
            *pbuf++ = *pstr;
        }
        pstr++;
    }
    *pbuf = '\0';
    return buf;
}

int _fill_peer_info(bt_peer *peer, be_node *node, ssize_t indent, char *key) {
    size_t i;

    indent = abs((int) indent);

    switch (node->type) {
        case BE_STR:
            if (!strcmp(key, "tracker id"))
                strcpy(peer->tracker_id, node->val.s);

            if (!strcmp(key, "peers"))
                strcpy(peer->peer_hashes, node->val.s);

            break;

        case BE_INT:
            if (!strcmp(key, "complete"))
                peer->complete = (int) node->val.i;
            if (!strcmp(key, "incomplete"))
                peer->incomplete = (int) node->val.i;
            if (!strcmp(key, "interval"))
                peer->interval = (int) node->val.i;

            break;

        case BE_LIST:
            for (i = 0; node->val.l[i]; ++i)
                _fill_peer_info(peer, node->val.l[i], indent + 1, "");

            break;

        case BE_DICT:
            for (i = 0; node->val.d[i].val; ++i)
                _fill_peer_info(peer, node->val.d[i].val, -(indent + 1), node->val.d[i].key);

            break;
    }
    return 1;
}

/**
* Returns 1 in case sucess
*/
int parse_info(bt_peer *peer, be_node *node) {
    return _fill_peer_info(peer, node, 0, "");
}


void decode_tracker_info(bt_args_t *bt_args, char *info) {
    be_node *node;
    node = load_node(info);

    be_dump(node);

    bt_peer *peer = malloc(sizeof(bt_peer));

    parse_info(peer, node);
    printf("complete: %i\n", peer->complete);
    printf("incomplete: %i\n", peer->incomplete);
    printf("interval: %i\n", peer->interval);
    printf("peers: %s\n", peer->peer_hashes);
    int num_peers = (int) (strlen(peer->peer_hashes) / 6);
    printf("peers amount: %i\n", num_peers);

    int i;
    int count = 0;

    for (i = 0; i < num_peers; i++) {
        uint32_t ip;
        uint16_t port;
        ip = (uint32_t) ((char *) peer->peer_hashes + count);
        count = count + 4;
        printf("ip: %i\n", ip);
        port = (uint16_t) ((char *) peer->peer_hashes + count);
        count = count + 2;
        printf("port: %hu\n", port);
        //IP stringad
        struct in_addr ip_addr;
        ip_addr.s_addr = htonl(ip);
        printf("The IP address is %s\n", inet_ntoa(ip_addr));

        char *id = malloc(21);
        memset(id, 0, 21);
        calc_id(inet_ntoa(ip_addr), port, id);
        printf("The Peer ID is %s\n", id);
        peer_t *peer_t1 = malloc(sizeof(peer_t));
        init_peer(peer_t1, id, inet_ntoa(ip_addr), port);
        char *hostname;
        add_peer(peer_t1, bt_args, hostname, port);
        free(peer_t1);
    }


}

/**
*
**/
char *read_file(char *file, long long *len) {
    struct stat st;
    char *ret = NULL;
    FILE *fp;

    if (stat(file, &st)) {
        return ret;
    }
    *len = st.st_size;

    fp = fopen(file, "r");
    if (!fp)
        return ret;

    ret = malloc((size_t) *len);
    if (!ret)
        return NULL;

    fread(ret, 1, (size_t) *len, fp);

    fclose(fp);

    return ret;
}

/**
* Copyright (c) 2014, Willem-Hendrik Thiart
* Use of this source code is governed by a BSD-style license that can be
* found in the LICENSE file.
*
* @file
* @brief Read bencoded data
* @author  Willem Thiart himself@willemthiart.com
* @version 0.1
*/

/**
* Carry length over to a new bencode object.
* This is done so that we don't exhaust the buffer */
static int __carry_length(
        bencode_t *be,
        const char *pos
) {
    assert(0 < be->len);
    return be->len - (pos - be->str);
}

/**
* @param end The point that we read out to
* @param val Output of number represented by string
* @return 0 if error; otherwise 1 */
static long int __read_string_int(
        const char *sp,
        const char **end,
        long int *val
) {
    *val = 0;

    if (!isdigit(*sp))
        return 0;

    /* work out number */
    do {
        *val *= 10;
        *val += *sp - '0';
        sp++;
    }
    while (isdigit(*sp));

    *end = sp;
    return 1;
}

int bencode_is_dict(
        const bencode_t *be
) {
    return be->str && *be->str == 'd';
}

int bencode_is_int(
        const bencode_t *be
) {
    return be->str && *be->str == 'i';
}

int bencode_is_list(
        const bencode_t *be
) {
    return be->str && *be->str == 'l';
}

int bencode_is_string(
        const bencode_t *be
) {
    const char *sp;

    sp = be->str;

    assert(sp);

    if (!isdigit(*sp))
        return 0;

    do sp++;
    while (isdigit(*sp));

    return *sp == ':';
}

/**
* Move to next item
* @param sp The bencode string we are processing
* @return Pointer to string on success, otherwise NULL */
static const char *__iterate_to_next_string_pos(
        bencode_t *be,
        const char *sp
) {
    bencode_t iter;

    bencode_init(&iter, sp, __carry_length(be, sp));

    if (bencode_is_dict(&iter)) {
        /* navigate to the end of the dictionary */
        while (bencode_dict_has_next(&iter)) {
            /* ERROR: input string is invalid */
            if (0 == bencode_dict_get_next(&iter, NULL, NULL, NULL))
                return NULL;
        }

        return iter.str + 1;
    }
    else if (bencode_is_list(&iter)) {
        /* navigate to the end of the list */
        while (bencode_list_has_next(&iter)) {
            /* ERROR: input string is invalid */
            if (-1 == bencode_list_get_next(&iter, NULL))
                return NULL;
        }

        return iter.str + 1;
    }
    else if (bencode_is_string(&iter)) {
        int len;
        const char *str;

        /* ERROR: input string is invalid */
        if (0 == bencode_string_value(&iter, &str, &len))
            return NULL;

        return str + len;
    }
    else if (bencode_is_int(&iter)) {
        const char *end;
        long int val;

        if (0 == __read_string_int(&iter.str[1], &end, &val))
            return NULL;

        assert(end[0] == 'e');

        return end + 1;
    }

    /* input string is invalid */
    return NULL;
}

static const char *__read_string_len(
        const char *sp,
        int *slen
) {
    *slen = 0;

    if (!isdigit(*sp))
        return NULL;

    do {
        *slen *= 10;
        *slen += *sp - '0';
        sp++;
    }
    while (isdigit(*sp));

    assert(*sp == ':');
    assert(0 <= *slen);

    return sp + 1;
}

void bencode_init(
        bencode_t *be,
        const char *str,
        const int len
) {
    memset(be, 0, sizeof(bencode_t));
    be->str = be->start = str;
    be->str = str;
    be->len = len;
    assert(0 < be->len);
}

int bencode_int_value(
        bencode_t *be,
        long int *val
) {
    const char *end;

    if (0 == __read_string_int(&be->str[1], &end, val))
        return 0;

    assert(end[0] == 'e');

    return 1;
}

int bencode_dict_has_next(
        bencode_t *be
) {
    const char *sp = be->str;

    assert(be);

    if (!sp
            /* at end of dict */
            || *sp == 'e'
            /* at end of string */
            || *sp == '\0'
            || *sp == '\r'
            /* at the end of the input string */
            || be->str >= be->start + be->len - 1) {
        return 0;
    }

    return 1;
}

int bencode_dict_get_next(
        bencode_t *be,
        bencode_t *be_item,
        const char **key,
        int *klen
) {
    const char *sp = be->str;
    const char *keyin;
    int len;

    assert(*sp != 'e');

    /* if at start increment to 1st key */
    if (*sp == 'd') {
        sp++;
    }

    /* can't get the next item if we are at the end of the dict */
    if (*sp == 'e') {
        return 0;
    }

    /* 1. find out what the key's length is */
    keyin = __read_string_len(sp, &len);

    /* 2. if we have a value bencode, lets put the value inside */
    if (be_item) {
        *klen = len;
        bencode_init(be_item, keyin + len, __carry_length(be, keyin + len));
    }

    /* 3. iterate to next dict key, or move to next item in parent */
    if (!(be->str = __iterate_to_next_string_pos(be, keyin + len))) {
        /*  if there isn't anything else or we are at the end of the string */
        return 0;
    }

#if 0
    /*  if at the end of bencode, check that the 'e' terminator is there */
    if (be->str == be->start + be->len - 1 && *be->str != 'e')
    {
        be->str = NULL;
        return 0;
    }
#endif

    assert(be->str);

    if (key) {
        *key = keyin;
    }

    return 1;
}

int bencode_string_value(
        bencode_t *be,
        const char **str,
        int *slen
) {
    const char *sp;

    *slen = 0;

    assert(bencode_is_string(be));

    sp = __read_string_len(be->str, slen);

    assert(sp);
    assert(0 < be->len);

    /*  make sure we still fit within the buffer */
    if (sp + *slen > be->start + (long int) be->len) {
        *str = NULL;
        return 0;
    }

    *str = sp;
    return 1;
}

int bencode_list_has_next(
        bencode_t *be
) {
    const char *sp;

    sp = be->str;

    /* empty list */
    if (*sp == 'l' &&
            sp == be->start &&
            *(sp + 1) == 'e') {
        be->str++;
        return 0;
    }

    /* end of list */
    if (*sp == 'e') {
        return 0;
    }

    return 1;
}

int bencode_list_get_next(
        bencode_t *be,
        bencode_t *be_item
) {
    const char *sp;

    sp = be->str;

#if 0 /* debugging */
    printf("%.*s\n", be->len - (be->str - be->start), be->str);
#endif

    /* we're at the end */
    if (!sp || *sp == 'e')
        return 0;

    if (*sp == 'l') {
        /* just move off the start of this list */
        if (be->start == be->str) {
            sp++;
        }
    }

    /* can't get the next item if we are at the end of the list */
    if (*sp == 'e') {
        be->str = sp;
        return 0;
    }

    /* populate the be_item if it is available */
    if (be_item) {
        bencode_init(be_item, sp, __carry_length(be, sp));
    }

    /* iterate to next value */
    if (!(be->str = __iterate_to_next_string_pos(be, sp))) {
        return -1;
    }

    return 1;
}

void bencode_clone(
        bencode_t *be,
        bencode_t *output
) {
    memcpy(output, be, sizeof(bencode_t));
}

int bencode_dict_get_start_and_len(
        bencode_t *be,
        const char **start,
        int *len
) {
    bencode_t ben, ben2;
    const char *ren;
    int tmplen;

    bencode_clone(be, &ben);
    *start = ben.str;
    while (bencode_dict_has_next(&ben))
        bencode_dict_get_next(&ben, &ben2, &ren, &tmplen);

    *len = ben.str - *start + 1;
    return 0;
}
