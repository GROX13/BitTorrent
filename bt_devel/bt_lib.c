#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <arpa/inet.h>

#include <curl/curl.h>
#include <openssl/sha.h> //hashing pieces

#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"

#define ECHOMAX 255

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

void reverse(char *x, int begin, int end) {
    char c;

    if (begin >= end)
        return;

    c = *(x + begin);
    *(x + begin) = *(x + end);
    *(x + end) = c;

    reverse(x, ++begin, --end);
}

int contact_tracker(bt_args_t *bt_args) {
    printf("Starting contact tracker:\n");
    printf("Announce: %s\n", bt_args->bt_info->announce);
    printf("Length: %d\n", bt_args->bt_info->length);
    printf("Name: %s\n", bt_args->bt_info->name);
    printf("Number of pieces: %u\n", bt_args->bt_info->num_pieces);
    printf("Piece length: %d\n", bt_args->bt_info->piece_length);

    char *file;
    long long leng;
    file = read_file(bt_args->torrent_file, &leng);

    char *hashed_info = malloc(21);
    int len = (int) strlen(strstr(strstr(file, "info"), "d"));
    SHA1((unsigned char const *) strstr(strstr(file, "info"), "d"), (size_t) len, (unsigned char *) hashed_info);

    int announce_len = (int) strlen(bt_args->bt_info->announce);
	
	char *request_to_send;
    request_to_send = malloc(100);

	//aq unda iyos: Port number this peer is listening on. 
	//Common behavior is for a downloader to try to listen on 
	//port 6881 and if that port is taken try 6882, then 6883, etc. and give up after 6889.
	char* port = "6969";
    sprintf(request_to_send, "%s/announce?info_hash=%s&peer_id=%s&port=%s"
                    "&downloaded=0&left=0&event=started", bt_args->bt_info->announce,
            url_encode(hashed_info), url_encode(generate_peer_id()), port);
    
	printf("Request URL for tracker: %s\n", request_to_send);
    return 0;	
}

void calc_id(char *ip, unsigned short port, char *id) {
    char data[256];
    int len;

    //format print
    len = snprintf(data, 256, "%s%u", ip, port);

    //id is just the SHA1 of the ip and port string
    SHA1((unsigned char *) data, (size_t) len, (unsigned char *) id);

    return;
}


/**
* init_peer(peer_t * peer, int id, char * ip, unsigned short port) -> int
*
*
* initialize the peer_t structure peer with an id, ip address, and a
* port. Further, it will set up the sockaddr such that a socket
* connection can be more easily established.
*
* Return: 0 on success, negative values on failure. Will exit on bad
* ip address.
*
**/
int init_peer(peer_t *peer, char *id, char *ip, unsigned short port) {

    struct hostent *hostinfo;
    //set the host id and port for referece
    memcpy(peer->id, id, ID_SIZE);
    peer->port = port;

    //get the host by name
    if ((hostinfo = gethostbyname(ip)) == NULL) {
        perror("gethostbyname failure, no such host?");
        herror("gethostbyname");
        exit(1);
    }

    //zero out the sock address
    bzero(&(peer->sockaddr), sizeof(peer->sockaddr));

    //set the family to AF_INET, i.e., Iternet Addressing
    peer->sockaddr.sin_family = AF_INET;

    //copy the address to the right place
    bcopy((char *) (hostinfo->h_addr),
            (char *) &(peer->sockaddr.sin_addr.s_addr),
            (size_t) hostinfo->h_length);

    //encode the port
    peer->sockaddr.sin_port = htons(port);

    return 0;

}

/**
* print_peer(peer_t *peer) -> void
*
* print out debug info of a peer
*
**/
void print_peer(peer_t *peer) {
    int i;

    if (peer) {
        printf("peer: %s:%u ",
                inet_ntoa(peer->sockaddr.sin_addr),
                peer->port);
        printf("id: ");
        for (i = 0; i < ID_SIZE; i++) {
            printf("%02x", peer->id[i]);
        }
        printf("\n");
    }
}

int _fill_info(bt_info_t *info_t, be_node *node, ssize_t indent, char *key) {
    size_t i;

    indent = abs((int) indent);

    switch (node->type) {
        case BE_STR:
            if (!strcmp(key, "announce"))
                strcpy(info_t->announce, node->val.s);

            if (!strcmp(key, "name"))
                strcpy(info_t->name, node->val.s);

            break;

        case BE_INT:
            if (!strcmp(key, "length"))
                info_t->length = (int) node->val.i;
            if (!strcmp(key, "pieces"))
            	info_t->num_pieces  = (int) node->val.i;
            if (!strcmp(key, "piece length"))
                info_t->piece_length = (int) node->val.i;

            break;

        case BE_LIST:
            for (i = 0; node->val.l[i]; ++i)
                _fill_info(info_t, node->val.l[i], indent + 1, "");

            break;

        case BE_DICT:
            for (i = 0; node->val.d[i].val; ++i)
                _fill_info(info_t, node->val.d[i].val, -(indent + 1), node->val.d[i].key);

            break;
    }
    return 1;
}

/**
* Returns 1 in case sucess
*/
int parse_bt_info(bt_info_t *bt_info, be_node *node) {
    return _fill_info(bt_info, node, 0, "");
}

