#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h> // internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <arpa/inet.h>

#include <openssl/sha.h> // hashing pieces

#include "bt_library.h"
#include "setup.h"
#include "bt_library.h"
#include "bt_bencode.h"


void calc_id(char *ip, unsigned short port, char *id)
{
    char data[256];
    int len;

    // format print
    len = snprintf(data, 256, "%s%u", ip, port);

    // id is just the SHA1 of the ip and port string
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
int init_peer(peer_t *peer, char *id, char *ip, unsigned short port)
{

    struct hostent *hostinfo;
    // set the host id and port for referece
    memcpy(peer->id, id, ID_SIZE);
    peer->port = port;

    // get the host by name
    if ((hostinfo = gethostbyname(ip)) ==  NULL)
    {
        perror("gethostbyname failure, no such host?");
        herror("gethostbyname");
        exit(1);
    }

    // zero out the sock address
    bzero(&(peer->sockaddr), sizeof(peer->sockaddr));

    // set the family to AF_INET, i.e., Iternet Addressing
    peer->sockaddr.sin_family = AF_INET;

    // copy the address to the right place
    bcopy((char *) (hostinfo->h_addr),
          (char *) & (peer->sockaddr.sin_addr.s_addr),
          (size_t) hostinfo->h_length);

    // encode the port
    peer->sockaddr.sin_port = htons(port);

    return 0;

}

/**
 * print_peer(peer_t *peer) -> void
 *
 * print out debug info of a peer
 *
 **/
void print_peer(peer_t *peer)
{
    int i;

    if (peer)
    {
        printf("peer: %s:%u ",
               inet_ntoa(peer->sockaddr.sin_addr),
               peer->port);
        printf("id: ");
        for (i = 0; i < ID_SIZE; i++)
        {
            printf("%02x", peer->id[i]);
        }
        printf("\n");
    }
}


int contact_tracker(bt_args_t *bt_args)
{
    return 0;
}

int sha1_piece(bt_args_t *bt_args, bt_piece_t *piece, unsigned char *hash)
{
    return 0;
}

int get_bitfield(bt_args_t *bt_args, bt_bitfield_t *bitfield)
{
    return 0;
}

int load_piece(bt_args_t *bt_args, bt_piece_t *piece)
{
    return 0;
}

int save_piece(bt_args_t *bt_args, bt_piece_t *piece)
{
    return 0;
}

int read_from_peer(peer_t *peer, bt_msg_t *msg)
{
    return 0;
}

int send_to_peer(peer_t *peer, bt_msg_t *msg)
{
    return 0;
}

int poll_peers(bt_args_t *bt_args)
{
    return 0;
}

int check_peer(peer_t *peer)
{
    return 0;
}

int drop_peer(peer_t *peer, bt_args_t *bt_args)
{
    return 0;
}

int add_peer(peer_t *peer, bt_args_t *bt_args, char *hostname, unsigned short port)
{
    return 0;
}

unsigned int select_id()
{
    return 0;
}

void _fill_info(bt_info_t *info_t, be_node *node, ssize_t indent, char *key)
{
    size_t i;

    indent = abs((int) indent);

    switch (node->type)
    {
    case BE_STR:
        if (strcmp(key, "announce"))
            strcpy(info_t->announce, node->val.s);

        if (strcmp(key, "name"))
            strcpy(info_t->name, node->val.s);
        break;

    case BE_INT:
        if (strcmp(key, "length"))
            info_t->length = node->val.i;
        //            if (strcmp(key, ""))
        //                info_t->num_pieces  = node->val.i;
        if (strcmp(key, "piece length"))
            info_t->piece_length  = node->val.i;

        break;

    case BE_LIST:

        for (i = 0; node->val.l[i]; ++i)
            _fill_info(info_t, node->val.l[i], indent + 1, "");


        break;

    case BE_DICT:
        for (i = 0; node->val.d[i].val; ++i)
        {


            _fill_info(info_t, node->val.d[i].val, -(indent + 1), node->val.d[i].key);
        }
        break;
    }
}

int parse_bt_info(bt_info_t *bt_info, be_node *node)
{
    _fill_info(bt_info, node, 0, "");
    printf("announce ----- > %s \n", bt_info->announce);
    printf("name ----- > %s \n", bt_info->name);
    printf("length ----- > %d \n", bt_info->length);
    return 1;
}
