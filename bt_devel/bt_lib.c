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
#include <bits/errno.h>
#include <asm-generic/errno-base.h>
#include <openssl/sha.h> //hashing pieces

#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"

#define ECHOMAX 255

void reverse(char *x, int begin, int end)
{
    char c;

    if (begin >= end)
        return;

    c = *(x + begin);
    *(x + begin) = *(x + end);
    *(x + end) = c;

    reverse(x, ++begin, --end);
}

struct my_string
{
    char *memory;
    size_t size;
};

static size_t my_string_append(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct my_string *mem = (struct my_string *) userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

char *send_http_request(char *url)
{
    CURL *curl_handle;
    CURLcode res;
    struct my_string header;
    struct my_string body;
    header.memory = malloc(1);
    header.size = 0;
    body.memory = malloc(1);
    body.size = 0;
    /* init the curl session */
    curl_handle = curl_easy_init();
    // curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, args);
    curl_easy_setopt(curl_handle, CURLOPT_HTTPGET, 1);
    /* specify URL to get */
    curl_easy_setopt(curl_handle, CURLOPT_URL, url);
    /* send all data to this function  */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, my_string_append);
    /* we pass our 'chunk' struct to the callback function */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *) &body);
    curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, (void *) &header);
    /* some servers don't like requests that are made without a user-agent
     field, so we provide one */
    curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
    /* get it! */
    res = curl_easy_perform(curl_handle);
    /* check for errors */
    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return NULL;
    }
    else
    {
        if (memcmp(body.memory, "d8:", 3) != 0)
        {
            printf("error\n%s\n", body.memory);
            return NULL;
        }
        else
        {
            return body.memory;
        }
    }
}

void _be_find(be_node *node, be_node *result, char *search)
{
    size_t i;

    switch (node->type)
    {
    case BE_STR:

        break;

    case BE_INT:

        break;

    case BE_LIST:

        for (i = 0; node->val.l[i]; ++i)
            _be_find(node->val.l[i], result, search);

        break;

    case BE_DICT:

        for (i = 0; node->val.d[i].val; ++i)
            _be_find(node->val.d[i].val, result, search);

        break;
    }
}

int contact_tracker(bt_args_t *bt_args)
{
    char *new_file;
    long long leng;

    new_file = read_file(bt_args->torrent_file, &leng);


    char *hashed_info = malloc(FILE_NAME_MAX);

    int len;
    char *inf = strstr(strstr(new_file, "info"), "d");

    len = 44478;

    SHA1((unsigned char const *) inf, len, (unsigned char *) hashed_info);

    char *request_to_send;
    request_to_send = malloc(FILE_NAME_MAX);
    memset(request_to_send, '\0', FILE_NAME_MAX);

    bt_args->info_hash = hashed_info;
    bt_args->bt_peer_id = "SatJan311528262015RR";
    //aq unda iyos: Port number this peer is listening on.
    //Common behavior is for a downloader to try to listen on
    //port 6881 and if that port is taken try 6882, then 6883, etc. and give up after 6889.
    // int port = INIT_PORT;
    // bt_args->bt_info->num_pieces = bt_args->bt_info->length / bt_args->bt_info->piece_length;
    // sprintf(request_to_send, "%s?info_hash=%s&peer_id=%s&port=%i"
    //         "&downloaded=0&left=1162936320&event=started&compact=1", bt_args->bt_info->announce,
    //         url_encode(hashed_info), url_encode(generate_peer_id()), port);

    // printf("Request URL for tracker: %s\n", request_to_send);

    // http://torrent.ubuntu.com:6969/announce?
    // info_hash=%5e%ef%fc%8e%b5%da%b4%ec%1c%a6%fd%ce%f0%93t%d7j%1389
    // &peer_id=SatJan311528262015RR
    // &port=6881
    // &downloaded=0
    // &left=0
    // &event=started

    request_to_send =
        "http://torrent.ubuntu.com:6969/"
        "announce?info_hash=%B4%15%C9%13d%3E%5F%F4%9F%E3%7D0K%BB%5En%11%ADQ%01"
        "&peer_id=SatJan311528262015RR"
        "&port=6681"
        "&key=2YUMOFZ3"
        "&event=started"
        "&uploaded=0"
        "&downloaded=0"
        "&left=1162936320"
        "&compact=1";

    char *result = send_http_request(request_to_send);
    if (result)
    {
        printf("Trackers responce is: %s\n", result);
        decode_tracker_info(bt_args, result);
    }
    return 0;
}

void calc_id(char *ip, unsigned short port, char *id)
{
    char data[256];
    int len;

    //format print
    len = snprintf(data, 256, "%s%u", ip, port);

    //id is just the SHA1 of the ip and port string
    SHA1((unsigned char *) data, (size_t) len, (unsigned char *) id);

    return;
}


/**
* add_peer(peer_t *peer, bt_args_t *bt_args, char *hostname, unsigned short port) -> int
*
* propogate a peer_t struct and add it to the bt_args structure
*
* Return: 0 on success, -1 on failiour
* */
int add_peer(peer_t *peer, bt_args_t *bt_args, char *hostname, unsigned short port)
{
    int i = 0;
    for (; i < MAX_CONNECTIONS; ++i)
        if (!bt_args->peers[i])
        {
            bt_args->peers[i] = peer;
            return 0;
        }
    return -1;
}

/**
* drop_peer(peer_t *peer, bt_args_t *bt_args) -> int
*
* drop an unresponsive or failed peer from the bt_args
*
* Return: 0 on success, -1 on failiour
* */
int drop_peer(peer_t *peer, bt_args_t *bt_args)
{
    int i = 0;
    for (; i < MAX_CONNECTIONS; ++i)
        if (strcmp((char const *) bt_args->peers[i]->id, (char const *) peer->id) == 0
                && bt_args->peers[i]->port == peer->port)
        {
            bt_args->peers[i] = NULL;
            return 0;
        }
    return 1;
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
    //set the host id and port for referece
    memcpy(peer->id, id, ID_SIZE);
    peer->port = port;

    //get the host by name
    if ((hostinfo = gethostbyname(ip)) == NULL)
    {
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
          (char *) & (peer->sockaddr.sin_addr.s_addr),
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

/* check status on peers, maybe they went offline? */
int check_peer(peer_t *peer)
{

    return 0;
}

/*check if peers want to send me something*/
int poll_peers(bt_args_t *bt_args)
{

    return 0;
}


//   char reserved_bytes[8];
//   char hash_info[20];
//   char peer_id[20];
/*send a msg to a peer*/
int send_to_peer(peer_t *peer, bt_msg_t *msg)
{
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
    switch (msg->type)
    {
    case BT_HANDSHAKE_T:;

        // datashi structuris gadawera

        char data[68];
        int size = sizeof(msg->payload.handshake.protocol_name_length);
        int offset = 0;
        memcpy(&data[offset], &msg->payload.handshake.protocol_name_length, size);
        offset = offset + size;
        size =  sizeof(msg->payload.handshake.protocol_name);
        memcpy(&data[offset], msg->payload.handshake.protocol_name, size);

        offset = offset + size;
        size = sizeof(msg->payload.handshake.reserved_bytes);
        memcpy(&data[offset], msg->payload.handshake.reserved_bytes, size);

        offset = offset + size;
        size = sizeof(msg->payload.handshake.hash_info);
        memcpy(&data[offset], msg->payload.handshake.hash_info, size);

        offset = offset + size;
        size = sizeof(msg->payload.handshake.peer_id);
        memcpy(&data[offset], msg->payload.handshake.peer_id, size);

        size = write(sockfd, data, sizeof(bt_handshake_t));
        // printf("sent size: %i\n", size);
        // char buff[68];
        // size = read(sockfd, buff, 68);
        // printf("received size: %i\n", size);
        // puts(buff);
        break;

    case BT_BITFIELD_T:

        break;

    case BT_REQUEST_T:

        break;

    case BT_CANCEL_T:

        break;
    case BT_PIECE_T:

        break;
    }
    return 0;
}

/*read a msg from a peer and store it in msg*/
int read_from_peer(peer_t *peer, bt_msg_t *msg)
{
    int socket_desc;
    //    struct sockaddr_in server;
    char server_reply[2000];

    //Create socket
    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1)
    {
        printf("Could not create socket");
    }

    //    server.sin_addr.s_addr = inet_addr("74.125.235.20");
    //    server.sin_family = AF_INET;
    //    server.sin_port = htons( 80 );

    //Connect to remote server
    if (connect(socket_desc , (struct sockaddr *)&peer->sockaddr , sizeof(peer->sockaddr)) < 0)
    {
        puts("connect error");
        return 1;
    }

    puts("Connected\n");
    while (1)
    {
        ssize_t count;

        count = read(socket_desc, server_reply, sizeof server_reply);
        if (count < 2000)

            break;

        puts(server_reply);
    }
    return 0;
}


int _fill_info(bt_info_t *info_t, be_node *node, ssize_t indent, char *key)
{
    size_t i;

    if (info_t == NULL || node == NULL || key == NULL)
        return 0;

    indent = abs((int) indent);

    switch (node->type)
    {
    case BE_STR:
        if (!strcmp(key, "announce"))
        {
            strcpy(info_t->announce, node->val.s);
            break;
        }

        if (!strcmp(key, "pieces"))
        {
            info_t->piece_hashes = &(node->val.s);
            break;
        }

        if (!strcmp(key, "name"))
            strcpy(info_t->name, node->val.s);

        break;

    case BE_INT:
        if (!strcmp(key, "length"))
        {
            info_t->length = (int) node->val.i;
            break;
        }

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
* parse_bt_info(bt_info_t *bt_info, be_node *node) -> int
*
* Returns 1 in case sucess, will exit on varios errors
*/
int parse_bt_info(bt_info_t *bt_info, be_node *node)
{
    return _fill_info(bt_info, node, 0, "");
}

