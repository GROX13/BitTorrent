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
#include "bt_sock.h"
#include "bt_io.h"
#define ECHOMAX 255

struct my_string
{
    char *memory;
    size_t size;
};

typedef struct thdata
{
    int th_num;
    bt_args_t *bt_args;
    peer_t *bt_peer_t;
} thdata;

static size_t _my_string_append(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct my_string *mem = (struct my_string *) userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

char *_send_http_request(char *URL)
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
    curl_easy_setopt(curl_handle, CURLOPT_URL, URL);
    /* send all data to this function  */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, _my_string_append);
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
            printf("Error\n%s\n", body.memory);
            free(header.memory);
            free(body.memory);
            return NULL;
        }
        else
        {
            free(header.memory);
            return body.memory;
        }
    }
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

    default:
        return -1;
    }
    return 1;
}


void _connect_function(void *ptr)
{
    thdata *data;
    data = ptr;

    int my_socket = create_socket(data->bt_peer_t->sockaddr);
    if (my_socket < 0)
    {
        drop_peer(data->bt_peer_t, data->bt_args);
        free(data->bt_peer_t);
        free(ptr);
    }
    else
    {
        data->bt_peer_t->socket_fd = my_socket;
        data->bt_peer_t->interested = 1;
        data->bt_peer_t->choked = -1;
        if (data->bt_args->verbose)
            print_peer(data->bt_peer_t);
        free(ptr);
    }
}

int contact_tracker(bt_args_t *bt_args)
{
    printf("Please wait ...\nConnecting with tracker.\n");

    char *new_file;
    long long leng;

    new_file = read_file(bt_args->torrent_file, &leng);

    if (!new_file)
        return 1;

    char *inf = strstr(strstr(new_file, "info"), "d");
    // length on ubuntu 14.04 torrent should be 44478
    long long len = be_len(inf);

    memset(bt_args->info_hash, '\0', BT_INFO_HASH_SIZE);
    memset(bt_args->bt_peer_id, '\0', BT_INFO_HASH_SIZE);
    SHA1((unsigned char const *) inf, (size_t) len, (unsigned char *) bt_args->info_hash);

    char *request_to_send = malloc(FILE_NAME_MAX);
    request_to_send = malloc(FILE_NAME_MAX);

    memset(request_to_send, '\0', FILE_NAME_MAX);
    memcpy(bt_args->bt_peer_id, generate_peer_id(), 20);

    //Port number this peer is listening on.
    //Common behavior is for a downloader to try to listen on
    //port 6881 and if that port is taken try 6882, then 6883, etc. and give up after 6889.
    uint16_t port = INIT_PORT;
    bt_args->bt_info->num_pieces = bt_args->bt_info->length / bt_args->bt_info->piece_length;
    sprintf(request_to_send,
            "%s?info_hash=%s&peer_id=%s&port=%hu&uploaded=0"
            "&downloaded=0&left=%d&event=started&compact=1",
            bt_args->bt_info->announce, url_encode(bt_args->info_hash),
            url_encode(bt_args->bt_peer_id), port, bt_args->bt_info->length);

    // correct request to send on ubuntu torrent

    //  http://torrent.ubuntu.com:6969/announce?
    //      info_hash=%B4%15%C9%13d%3E%5F%F4%9F%E3%7D0K%BB%5En%11%ADQ%01
    //      announce?info_hash=%b4%15%c9%13d%3e_%f4%9f%e3%7d0K%bb%5en%11%adQ%01
    //      &peer_id=TueFeb32137332015RRR&port=6681&event=started&uploaded=0
    //      &downloaded=0&left=1162936320&compact=1

    if (bt_args->verbose)
        printf("Request URL for tracker: %s\n", request_to_send);

    char *result = _send_http_request(request_to_send);
    if (result)
    {
        be_node *node = be_decoden(result, (long long int) be_len);

        if (bt_args->verbose)
            be_dump(node);

        bt_peer *peer = malloc(sizeof(bt_peer));

        // parse_info(peer, node);
        _fill_peer_info(peer, node, 0, "");

        int num_peers = 0;

        char *peer_num = strstr(result, "peers");
        if (peer_num == NULL)
        {
            printf("Something went wrong in parsing received data!\n");
            free(result);
            return 1;
        }
        int i = 0;
        peer_num += 5;
        char buff[20];
        memset(buff, 0, 20);
        for (; *peer_num != ':'; peer_num++, i++)
            buff[i] = *peer_num;

        char *endptr;
        num_peers = (int) strtol(buff, &endptr, 10) / 6;

        if (num_peers == 0)
        {
            free(result);
            return 1;
        }
        int count = 0;
        pthread_t *thread = malloc(num_peers * sizeof(pthread_t));
        printf("Connecting with peers.\n");
        for (i = 0; i < num_peers; i++)
        {
            uint32_t ip = *(uint32_t *) (peer->peer_hashes + count);
            count = (int) (count + sizeof(uint32_t));
            port = *(uint16_t *) (peer->peer_hashes + count);
            count = (int) (count + sizeof(uint16_t));

            peer_t *my_peer_t = malloc(sizeof(peer_t));

            my_peer_t->interested = -1;
            my_peer_t->choked = -1;

            //IP to string
            struct in_addr ip_addr;
            ip_addr.s_addr = ip;

            char *id = malloc(21);
            memset(id, 0, 21);
            calc_id(inet_ntoa(ip_addr), port, id);
            memset(my_peer_t->id, 0, ID_SIZE);
            strcpy((char *) my_peer_t->id, id);

            init_peer(my_peer_t, id, inet_ntoa(ip_addr), htons(port));
            add_peer(my_peer_t, bt_args, inet_ntoa(ip_addr), port);

            thdata *data = malloc(sizeof(thdata));

            data->th_num = i;
            data->bt_args = bt_args;
            data->bt_peer_t = my_peer_t;

            pthread_create (&thread[i], NULL, (void *) &_connect_function, (void *) data);
        }

        for (i = 0; i < num_peers; i++);
        pthread_join(thread[i], NULL);
    }
    else
    {
        printf("Something went wrong!\n");
        return 1;
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
        if (bt_args->peers[i])
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
    int nfds;
    for (;;)
    {
        nfds = epoll_wait(bt_args->epollfd, bt_args->poll_sockets, MAX_CONNECTIONS, -1);
        if (nfds == -1)
        {
            perror("epoll_pwait");
            break;
            //            exit(EXIT_FAILURE);
        }

        //        for (n = 0; n < nfds; ++n) {
        //            if (bt_args->poll_sockets[n].data.fd == listen_sock) {
        //                conn_sock = accept(listen_sock,
        //                        (struct sockaddr *) &local, &addrlen);
        //                if (conn_sock == -1) {
        //                    perror("accept");
        //                    break;
        ////                    exit(EXIT_FAILURE);
        //                }
        //                setnonblocking(conn_sock);
        //                ev.events = EPOLLIN | EPOLLET;
        //                ev.data.fd = conn_sock;
        //                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, conn_sock,
        //                        &ev) == -1) {
        //                    perror("epoll_ctl: conn_sock");
        //                    break;
        ////                    exit(EXIT_FAILURE);
        //                }
        //            } else {
        //                do_use_fd(events[n].data.fd);
        //            }
        //        }
    }
    return -1;
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
    int sockfd = peer->socket_fd, ret_val = -1;

    uint32_t msg_size = htonl(msg->length);
    uint8_t msg_type;
    // May need in future
    uint32_t tmp_1;
    uint32_t tmp_2;
    uint32_t tmp_3;
    // Allocate needed space
    void *buff = malloc(msg->length + sizeof(uint32_t));

    switch (msg->type)
    {

    case BT_BITFIELD_T:
        msg_type = BT_BITFILED;
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &msg_type, sizeof(uint8_t));
        memcpy((char *) buff + sizeof(uint32_t) +
               sizeof(uint8_t), msg->payload.bitfiled.bitfield, msg->payload.bitfiled.size);
        ret_val = (int) send(sockfd, buff, msg->length + sizeof(uint32_t), 0);
        break;

    case BT_REQUEST_T:
        msg_type = BT_REQUEST;
        tmp_1 = htonl(msg->payload.request.index);
        tmp_2 = htonl(msg->payload.request.begin);
        tmp_3 = htonl(msg->payload.request.length);
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &msg_type, sizeof(uint8_t));
        memcpy((char *) buff + sizeof(uint32_t) + sizeof(uint8_t),
               &tmp_1, sizeof(uint32_t));
        memcpy((char *) buff + 2 * sizeof(uint32_t) + sizeof(uint8_t),
               &tmp_2, sizeof(uint32_t));
        memcpy((char *) buff + 3 * sizeof(uint32_t) + sizeof(uint8_t),
               &tmp_3, sizeof(uint32_t));
        ret_val = (int) send(sockfd, buff, msg->length + sizeof(uint32_t), 0);
        break;

    case BT_CANCEL_T:
        msg_type = BT_CANCEL;
        tmp_1 = htonl(msg->payload.request.index);
        tmp_2 = htonl(msg->payload.request.begin);
        tmp_3 = htonl(msg->payload.request.length);
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &msg_type, sizeof(uint8_t));
        memcpy((char *) buff + sizeof(uint32_t) + sizeof(uint8_t),
               &tmp_1, sizeof(uint32_t));
        memcpy((char *) buff + 2 * sizeof(uint32_t) + sizeof(uint8_t),
               &tmp_2, sizeof(uint32_t));
        memcpy((char *) buff + 3 * sizeof(uint32_t) + sizeof(uint8_t),
               &tmp_3, sizeof(uint32_t));
        ret_val = (int) send(sockfd, buff, msg->length + sizeof(uint32_t), 0);
        break;

    case BT_PIECE_T:
        msg_type = BT_PIECE;
        tmp_1 = htonl(msg->payload.piece.index);
        tmp_2 = htonl(msg->payload.piece.begin);
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &msg_type, sizeof(uint8_t));
        memcpy((char *) buff + sizeof(uint32_t) + sizeof(uint8_t),
               &tmp_1, sizeof(uint32_t));
        memcpy((char *) buff + 2 * sizeof(uint32_t) + sizeof(uint8_t),
               &tmp_2, sizeof(uint32_t));
        memcpy((char *) buff + 3 * sizeof(uint32_t) + sizeof(uint8_t),
               &msg->payload.piece.piece, msg->length - (2 * sizeof(uint32_t) + sizeof(uint8_t)));
        ret_val = (int) send(sockfd, buff, msg->length + sizeof(uint32_t), 0);
        break;

    // not tested but correct :)
    case BT_INTERESTED_T:
        msg_type = BT_INTERSTED;
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &msg_type, sizeof(uint8_t));
        ret_val = (int) send(sockfd, buff, msg->length + sizeof(uint32_t), 0);
        break;

    case BT_CHOKE_T:
        msg_type = BT_CHOKE;
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &msg_type, sizeof(uint8_t));
        ret_val = (int) send(sockfd, buff, msg->length + sizeof(uint32_t), 0);
        break;

    case BT_UNCHOKE_T:
        msg_type = BT_UNCHOKE;
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &msg_type, sizeof(uint8_t));
        ret_val = (int) send(sockfd, buff, msg->length + sizeof(uint32_t), 0);
        break;

    case BT_NOT_INTERESTED_T:
        msg_type = BT_NOT_INTERESTED;
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &msg_type, sizeof(uint8_t));
        ret_val = (int) send(sockfd, buff, msg->length + sizeof(uint32_t), 0);
        break;

    case BT_HAVE_T:
        msg_type = BT_HAVE;
        tmp_1 = htonl(msg->payload.have);
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        memcpy((char *) buff + sizeof(uint32_t), &msg_type, sizeof(uint8_t));
        memcpy((char *) buff + sizeof(uint32_t) + sizeof(uint8_t), &tmp_1, sizeof(uint32_t));
        ret_val = (int) send(sockfd, buff, msg->length + sizeof(uint32_t), 0);
        break;

    case BT_KEEP_ALIVE_T:
        memcpy((char *) buff, &msg_size, sizeof(uint32_t));
        ret_val = (int) send(sockfd, buff, msg->length + sizeof(uint32_t), 0);
        break;

    default:
        break;
    }

    free(buff);
    return ret_val;
}

/*read a msg from a peer and store it in msg*/
int read_from_peer(peer_t *peer, bt_msg_t *msg)
{
    int sockfd = peer->socket_fd;

    uint32_t msg_len = 0, tmp_1 = 0, tmp_2 = 0, tmp_3 = 0;
    uint8_t msg_id = 0;

    if (recv(sockfd, &msg_len, sizeof(uint32_t), 0) <= 0) return -1;
    msg_len = ntohl(msg_len);
    msg->length = msg_len;

    if (recv(sockfd, &msg_id, sizeof(uint8_t), 0) <= 0) return -1;

    switch (msg_id)
    {

    case BT_CHOKE:
        msg->length = msg_len;
        msg->type = BT_CHOKE_T;
        break;

    case BT_UNCHOKE:
        msg->length = msg_len;
        msg->type = BT_UNCHOKE_T;
        break;

    case BT_INTERSTED:
        msg->length = msg_len;
        msg->type = BT_INTERESTED_T;
        break;

    case BT_NOT_INTERESTED:
        msg->length = msg_len;
        msg->type = BT_NOT_INTERESTED_T;
        break;

    case BT_HAVE:
        msg->length = msg_len;
        msg->type = BT_HAVE_T;
        if (recv(sockfd, &tmp_1, sizeof(uint32_t), 0) <= 0) return -1;
        msg->payload.have = ntohl(tmp_1);
        break;

    case BT_BITFILED:
        msg->length = msg_len;
        msg->type = BT_BITFIELD_T;
        msg->payload.bitfiled.size = msg_len - sizeof(uint8_t);
        msg->payload.bitfiled.bitfield = malloc(msg->payload.bitfiled.size);
        if (recv(sockfd, &msg->payload.bitfiled.bitfield,
                 msg->payload.bitfiled.size, 0) <= 0) return -1;
        break;

    case BT_REQUEST:
        msg->length = msg_len;
        msg->type = BT_REQUEST_T;
        if (recv(sockfd, &tmp_1,
                 sizeof(uint32_t), 0) <= 0) return -1;
        if (recv(sockfd, &tmp_2,
                 sizeof(uint32_t), 0) <= 0) return -1;
        if (recv(sockfd, &tmp_3,
                 sizeof(uint32_t), 0) <= 0) return -1;
        msg->payload.request.index = ntohl(tmp_1);
        msg->payload.request.begin = ntohl(tmp_2);
        msg->payload.request.length = ntohl(tmp_3);
        break;

    case BT_PIECE:
        msg->length = msg_len;
        msg->type = BT_PIECE_T;
        if (recv(sockfd, &tmp_1,
                 sizeof(uint32_t), 0) <= 0) return -1;
        if (recv(sockfd, &tmp_2,
                 sizeof(uint32_t), 0) <= 0) return -1;
        msg->payload.piece.size = msg_len - (2 *  sizeof(uint32_t) + sizeof(uint8_t) );

        msg->payload.piece.index = tmp_1;
        msg->payload.piece.begin = tmp_2;
        msg->payload.piece.piece = malloc(msg->payload.piece.size);
        if (recv(sockfd, &msg->payload.piece.piece, msg->payload.piece.size, 0) <= 0) return -1;
        break;

    case BT_CANCEL:
        msg->length = msg_len;
        msg->type = BT_CANCEL_T;
        if (recv(sockfd, &tmp_1,
                 sizeof(uint32_t), 0) <= 0) return -1;
        if (recv(sockfd, &tmp_2,
                 sizeof(uint32_t), 0) <= 0) return -1;
        if (recv(sockfd, &tmp_3,
                 sizeof(uint32_t), 0) <= 0) return -1;
        msg->payload.request.index = ntohl(tmp_1);
        msg->payload.request.begin = ntohl(tmp_2);
        msg->payload.request.length = ntohl(tmp_3);
        break;

    default:
        if (msg_len == 0)
        {
            msg->length = msg_len;
            msg->type = BT_KEEP_ALIVE_T;
        }
        break;
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

/*load the bitfield into bitfield*/
int get_bitfield(bt_args_t *bt_args, bt_bitfield_t *bitfield){
	bitfield = malloc(sizeof(bt_bitfield_t));
	memcpy(bitfield, &bt_args->bitfield, sizeof(bt_bitfield_t));
	return 0;
}

/* save a piece of the file */
int save_piece(bt_args_t *bt_args, bt_piece_t *piece_t){
	int fd = create_file_descriptor(bt_args->save_file);
	size_t len = bt_args->bt_info->piece_length;
	void* ptr = malloc(len);
	memcpy(ptr, piece_t->piece, len);
	int save = save_data_to_file(ptr, len - piece_t->begin, piece_t->index*len+ piece_t->begin, fd, bt_args->save_file);
	return save;
}

/*load a piece of the file into piece */
int load_piece(bt_args_t *bt_args, bt_piece_t *piece_t){
	int fd = create_file_descriptor(bt_args->save_file);
	size_t len = bt_args->bt_info->piece_length;
	void * ptr = malloc(len);
	int load = load_data_from_file(ptr, len - piece_t->begin, piece_t->index*len+ piece_t->begin, fd, bt_args->save_file);
	memcpy(piece_t->piece, ptr, len);
	return load;
}




