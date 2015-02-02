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

/**
*
* */
int create_socket(char *ip_addr, unsigned short port)
{
    int socket_desc;
    struct sockaddr_in server;

    //Create socket
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }

    server.sin_addr.s_addr = inet_addr(ip_addr);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    //Connect to remote server
    if (connect(socket_desc, (struct sockaddr *) &server, sizeof(server)) < 0)
    {
        puts("connect error");
        return 1;
    }
    puts("Connected");

    return socket_desc;
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

    if (current_time == ((time_t) - 1))
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

int _fill_peer_info(bt_peer *peer, be_node *node, ssize_t indent, char *key)
{
    size_t i;

    indent = abs((int) indent);

    switch (node->type)
    {
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
int parse_info(bt_peer *peer, be_node *node)
{
    return _fill_peer_info(peer, node, 0, "");
}


void decode_tracker_info(bt_args_t *bt_args, char *info)
{
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

    for (i = 0; i < num_peers; i++)
    {
        uint32_t ip;
        uint16_t port;
        ip = *(uint32_t *) (peer->peer_hashes + count);
        count = count + 4;
        port = *(uint16_t *) (peer->peer_hashes + count);
        count = count + 2;
        //IP stringad
        struct in_addr ip_addr;
        ip_addr.s_addr = ip;

        char *id = malloc(21);
        memset(id, 0, 21);
        calc_id(inet_ntoa(ip_addr), port, id);
        peer_t *peer_t1 = malloc(sizeof(peer_t));
        init_peer(peer_t1, id, inet_ntoa(ip_addr), port);
        // char *hostname;
        add_peer(peer_t1, bt_args, NULL, port);
        print_peer(peer_t1);
        //free(peer_t1);
    }

}

int handshake(peer_t *peer, bt_handshake_t msg) {
    int sockfd;
    struct sockaddr_in addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
        perror("Couldn't create the socket");

    addr.sin_family = AF_INET;
    addr.sin_port = htons(peer->sockaddr.sin_port);
    addr.sin_addr = peer->sockaddr.sin_addr;
    //peer->sockaddr
    if (connect (sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1)
    {
        perror("Connection Problem");
        return 1;
    }

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
    printf("____________\n");
    printf("sent size: %i\n", size);

    char buff[2000];
    memset(buff, '\0', 2000);
    size = (int) read(sockfd, buff, 2000);
    printf("received size: %i\nreceived %s\n", size, buff);
	
	if(size == 68){
		memcpy(&peer->id, &buff[48], 20);
		printf("PEER ID IS: %s\n", peer->id);
		
		
	}	

    size = (int) read(sockfd, buff, 2000);
	
    printf("received size: %i\nreceived %s\n", size, buff);
    printf("____________\n");
	uint8_t msg_id = *((uint8_t *) &buff[4]);
	printf("Message ID is: %i\n", msg_id);
	switch (msg_id)
    {

    case BT_CHOKE:
		peer->choked = 0;
        break;

    case BT_UNCHOKE:
		peer->choked = 1;
        break;

    case BT_INTERSTED:
		peer->interested = 0;	
        break;
    case BT_NOT_INTERESTED:
		peer->interested = 1;	
        break;

	case BT_HAVE:

        break;

    case BT_BITFILED:;
		bt_bitfield_t *bt_bitfield = malloc(sizeof(bt_bitfield_t));
		bt_bitfield->size = (size_t)(size - 5);
		printf("bitfield size is : %i\n ", bt_bitfield->size);
		memcpy(bt_bitfield->bitfield, &buff[5], bt_bitfield->size); 
        break;

    case BT_REQUEST:;
		bt_request_t *bt_request = malloc(sizeof(bt_request_t));
		//vici rom ar mushaobs, magram sxvnairad ver vanicheb da gavasworot
		bt_request->index = *(int*)&buff[5];
		bt_request->begin = *(int*)&buff[9];
		bt_request->length = *(int*)&buff[13];
        break;

    case BT_PIECE:;
		bt_piece_t * bt_piece = malloc(sizeof(bt_piece_t));
		//vici rom ar mushaobs, magram sxvnairad ver vanicheb da gavasworot
		int block_size = *(int*)&buff[0];
		bt_piece->index = *(int*)&buff[5];
		bt_piece->begin = *(int*)&buff[9];
		memcpy(bt_piece->piece, &buff[13], block_size);
        break;

	case BT_CANCEL:

        break;

    default:
        break;
    }
	
    return 1;
}

/**
*
**/
char *read_file(char *file, long long *len)
{
    struct stat st;
    char *ret = NULL;
    FILE *fp;

    if (stat(file, &st))
    {
        return ret;
    }
    *len = st.st_size;

    fp = fopen(file, "r");
    if (!fp)
        return ret;

    ret = malloc((size_t) * len);
    if (!ret)
        return NULL;

    fread(ret, 1, (size_t) *len, fp);

    fclose(fp);

    return ret;
}

