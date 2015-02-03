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
#include <pthread.h>
#include <monetary.h>
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

int contact_tracker(bt_args_t *bt_args)
{
    char *new_file;
    long long leng;

    new_file = read_file(bt_args->torrent_file, &leng);

    char *inf = strstr(strstr(new_file, "info"), "d");
    // length on ubuntu 14 should be 44478
    long long len = be_len(inf);

    memset(bt_args->info_hash, '\0', BT_INFO_HASH_SIZE);
    memset(bt_args->bt_peer_id, '\0', BT_INFO_HASH_SIZE);
    SHA1((unsigned char const *) inf, (size_t) len, (unsigned char *) bt_args->info_hash);

    char *request_to_send = malloc(FILE_NAME_MAX);
    request_to_send = malloc(FILE_NAME_MAX);

    memset(request_to_send, '\0', FILE_NAME_MAX);
    memcpy(bt_args->bt_peer_id, generate_peer_id(), 20);
    //aq unda iyos: Port number this peer is listening on.
    //Common behavior is for a downloader to try to listen on
    //port 6881 and if that port is taken try 6882, then 6883, etc. and give up after 6889.
    int port = INIT_PORT;
    bt_args->bt_info->num_pieces = bt_args->bt_info->length / bt_args->bt_info->piece_length;
    sprintf(request_to_send,
            "%s?info_hash=%s&peer_id=%s&port=%i&uploaded=0"
            "&downloaded=0&left=%d&event=started&compact=1",
            bt_args->bt_info->announce, url_encode(bt_args->info_hash),
            url_encode(bt_args->bt_peer_id), port, bt_args->bt_info->length);

    /*
     * correct request to send on ubuntu torrent
     *
     *  "http://torrent.ubuntu.com:6969/"
     *      "announce?info_hash=%B4%15%C9%13d%3E%5F%F4%9F%E3%7D0K%BB%5En%11%ADQ%01"
     *      "announce?info_hash=%b4%15%c9%13d%3e_%f4%9f%e3%7d0K%bb%5en%11%adQ%01"
     *      "&peer_id=TueFeb32137332015RRR"
     *      "&port=6681"
     *      "&event=started"
     *      "&uploaded=0"
     *      "&downloaded=0"
     *      "&left=1162936320"
     *      "&compact=1";
     */

    printf("Request URL for tracker: %s\n", request_to_send);
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


/**
*  char reserved_bytes[8];
*  char hash_info[20];
*  char peer_id[20];
*  send a msg to a peer
*
* Returns negative on error, positive on sucess
**/
int send_to_peer(peer_t *peer, bt_msg_t *msg)
{
//    int sockfd;
    ssize_t ret_val = -1;
//    struct sockaddr_in addr;
//    sockfd = socket(AF_INET, SOCK_STREAM, 0);
//    if (sockfd == -1)
//        perror("Couldn't create the socket");
//
//    addr.sin_family = AF_INET;
//    addr.sin_port = htons(peer->sockaddr.sin_port);
//    addr.sin_addr = peer->sockaddr.sin_addr;
//
//    // (peer->sockaddr)
//
//
//    if (connect(sockfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) == -1)
//    {
//        perror("Connection Problem");
//        return (int) ret_val;
//    }

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


    uint32_t msg_size = htonl(msg->length);
    uint8_t msg_type;
    // Allocate needed space
    void *buff = malloc(msg_size + sizeof(uint32_t));
    uint8_t b = 2;
    uint32_t a = htonl(1);
    switch (msg->type)
    {

    case BT_BITFIELD_T:
        msg_type = BT_BITFILED;
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &msg_type, sizeof(uint8_t));
        memcpy((char *) buff + sizeof(uint32_t) + sizeof(uint8_t), msg->payload.bitfiled.bitfield, msg->payload.bitfiled.size);
        ret_val = write(sockfd, buff, msg_size);
        break;

    case BT_REQUEST_T:

        msg_size = sizeof(uint32_t) + sizeof(uint8_t);
            buff = malloc(msg_size);
        memcpy((char *) buff, &a, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &b, sizeof(uint8_t));
//        memcpy((char *) buff + sizeof(uint32_t) + sizeof(uint8_t),
//               &msg->payload.request.index, sizeof(uint32_t));
//        memcpy((char *) buff + 2 * sizeof(uint32_t) + sizeof(uint8_t),
//               &msg->payload.request.begin, sizeof(uint32_t));
//        memcpy((char *) buff + 3 * sizeof(uint32_t) + sizeof(uint8_t),
//               &msg->payload.request.length, sizeof(uint32_t));
        print_bytes(buff);

        ret_val = write(sockfd, buff, msg_size);
            printf("%d\n", (int) ret_val);
        break;

    case BT_CANCEL_T:
        msg_type = BT_CANCEL;
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &msg_type, sizeof(uint8_t));
        memcpy((char *) buff + sizeof(uint32_t) + sizeof(uint8_t),
               &msg->payload.request.index, sizeof(uint32_t));
        memcpy((char *) buff + 2 * sizeof(uint32_t) + sizeof(uint8_t),
               &msg->payload.request.begin, sizeof(uint32_t));
        memcpy((char *) buff + 3 * sizeof(uint32_t) + sizeof(uint8_t),
               &msg->payload.request.length, sizeof(uint32_t));
        ret_val = write(sockfd, buff, msg_size);
        break;
    case BT_PIECE_T:
        msg_type = BT_PIECE;
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &msg_type, sizeof(uint8_t));
        memcpy((char *) buff + sizeof(uint32_t) + sizeof(uint8_t),
               &msg->payload.piece.index, sizeof(uint32_t));
        memcpy((char *) buff + 2 * sizeof(uint32_t) + sizeof(uint8_t),
               &msg->payload.piece.begin, sizeof(uint32_t));
        memcpy((char *) buff + 3 * sizeof(uint32_t) + sizeof(uint8_t),
               &msg->payload.piece.piece, msg_size - (3 * sizeof(uint32_t) + sizeof(uint8_t)));
        ret_val = write(sockfd, buff, msg_size);
        break;
    case BT_INTERESTED_T:
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &msg_type, sizeof(uint8_t));
        ret_val = write(sockfd, buff, msg_size);
        break;
    default:
        break;
    }

    free(buff);
    return (int) ret_val;
}

/*
 * This will handle connection for each client
 * */
void *_connection_handler(void *socket_desc)
{
    //Get the socket descriptor
    int sock = *(int *) socket_desc;

    char *message;

    //Send some messages to the client
    message = "Greetings! I am your connection handler\n";
    write(sock, message, strlen(message));

    message = "Its my duty to communicate with you";
    write(sock, message, strlen(message));

    //Free the socket pointer
    free(socket_desc);

    return 0;
}

/*read a msg from a peer and store it in msg*/
int read_from_peer(peer_t *peer, bt_msg_t *msg)
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
    int msg_len = 0;
    int size = (int) read(sockfd, &msg_len, sizeof(int));
    msg_len = ntohl(msg_len);
    msg->length = msg_len;
    printf("Message length is: %i\n", msg_len);
    printf("%d\n", size);

    uint8_t msg_id;
    size = (int) read(sockfd, &msg_id, sizeof(char));

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
        msg->type = BT_INTERESTED_T;
        break;
    case BT_NOT_INTERESTED:
        peer->interested = 1;
        break;

    case BT_HAVE:

        break;

    case BT_BITFILED:;
        msg->type =  BT_BITFIELD_T;
        bt_bitfield_t *bt_bitfield = malloc(sizeof(bt_bitfield_t));
        bt_bitfield->size = (size_t)(msg_len - 1);
        printf("bitfield size is : %zu\n", bt_bitfield->size);
        bt_bitfield->bitfield = malloc(bt_bitfield->size);
        size = (int) read(sockfd, bt_bitfield->bitfield, bt_bitfield->size);
        memcpy(&msg->payload.bitfiled, bt_bitfield, sizeof(bt_bitfield_t));
		puts("blaaa");
        break;

    case BT_REQUEST:;
        msg->type = BT_REQUEST_T;
        bt_request_t *bt_request = malloc(sizeof(bt_request_t));
        size = (int) read(sockfd, &bt_request->index, sizeof(int));
        size = (int) read(sockfd, &bt_request->begin, sizeof(int));
        size = (int) read(sockfd, &bt_request->length, sizeof(int));
        memcpy(&msg->payload.request, bt_request, sizeof(bt_request_t));
        break;
    //es ar vici sworia tu ara
    case BT_PIECE:;
        msg->type = BT_PIECE_T;
        bt_piece_t *bt_piece = malloc(sizeof(bt_piece_t));
        int block_len = msg_len - 9;
        size = (int) read(sockfd, &bt_piece->index, sizeof(int));
        size = (int) read(sockfd, &bt_piece->begin, sizeof(int));
        size = (int) read(sockfd, &bt_piece->piece, block_len);
        memcpy(&msg->payload.piece, bt_piece, sizeof(bt_piece_t));
        break;

    case BT_CANCEL:
        msg->type = BT_CANCEL_T;
        break;

    default:
        break;
    }

    return 0;
    /* int socket_desc, new_socket, c, *new_sock;
     struct sockaddr_in server, client;
     char *message;

     //Create socket
     socket_desc = socket(AF_INET, SOCK_STREAM, 0);
     if (socket_desc == -1)
     {
         printf("Could not create socket");
     }

     //Prepare the sockaddr_in structure
     server.sin_family = AF_INET;
     server.sin_addr.s_addr = INADDR_ANY;
     server.sin_port = htons(8888);

     //Bind
     if (bind(socket_desc, (struct sockaddr *) &server, sizeof(server)) < 0)
     {
         puts("bind failed");
         return 1;
     }
     puts("bind done");

     //Listen
     listen(socket_desc, 3);

     //Accept and incoming connection
     puts("Waiting for incoming connections...");
     c = sizeof(struct sockaddr_in);
     while ((new_socket = accept(socket_desc, (struct sockaddr *) &client, (socklen_t *) &c)))
     {
         puts("Connection accepted");

         //Reply to the client
         message = "Hello Client , I have received your connection. And now I will assign a handler for you\n";
         write(new_socket, message, strlen(message));

         pthread_t sniffer_thread;
         new_sock = malloc(1);
         *new_sock = new_socket;

         if (pthread_create(&sniffer_thread, NULL, _connection_handler, (void *) new_sock) < 0)
         {
             perror("could not create thread");
             return 1;
         }

         //Now join the thread , so that we dont terminate before the thread
         //pthread_join( sniffer_thread , NULL);
         puts("Handler assigned");
     }

     if (new_socket < 0)
     {
         perror("accept failed");
         return 1;
     }
    */
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
typedef struct
{
    int index; //which piece index
    int begin; //offset within piece
    char piece[0]; //pointer to start of the data for a piece
} bt_piece_t;

/* save a piece of the file */
int save_piece(bt_args_t *bt_args, bt_piece_t *piece){
	FILE *file = bt_args->f_save;
		
	return 0;
}








