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
    char *file;
    long long leng;
    file = read_file(bt_args->torrent_file, &leng);
    puts(file);
    printf("%i\n", (int) strlen(file));
    puts(strstr(strstr(file, "info"), "d"));
    char *hashed_info = malloc(21);
    int len = (int) strlen(strstr(strstr(file, "info"), "d"));
    printf("len is %i\n", len);
    SHA1((unsigned char const *) strstr(strstr(file, "info"), "d"), (size_t) len, (unsigned char *) hashed_info);
    puts(hashed_info);
    puts(bt_args->bt_info->announce);

    int announce_len = (int) strlen(bt_args->bt_info->announce);
    char *announce = malloc((size_t) announce_len);
    strcpy(announce, bt_args->bt_info->announce);
    reverse(announce, 0, announce_len - 1);
    char port[5];
    int port_index = (int) strlen(strstr(announce, ":"));
    strcpy(port, (char *) bt_args->bt_info->announce + port_index);
    puts(port);
    memset(announce, '\0', (size_t) announce_len);
    strncpy(announce, bt_args->bt_info->announce, (size_t) (port_index - 1));

    char *new_announce = malloc((size_t) announce_len);
    memset(new_announce, '\0', (size_t) announce_len);
    puts(strstr(announce, ":"));
    strcpy(new_announce, (char *) strstr(announce, ":") + 3);

    puts(new_announce);

	char *requestToSend;
    requestToSend = malloc(100);
    puts(url_encode(bt_args->bt_info->announce));
    sprintf(requestToSend, "GET /announce?info_hash=%s&peer_id=%s&port=%s"
                    "&downloaded=0&left=0&event=started HTTP/1.0",
            url_encode(hashed_info), url_encode(generate_peer_id()), url_encode(port));
    printf("\n%s \nto send \n", requestToSend);

	char *host;
	host = malloc(strlen(new_announce)+6);
	sprintf(host, "Host: %s", new_announce);

//    CURL *curl;
//	CURLcode res;
//	curl = curl_easy_init();
//  	if(curl) {
//    struct curl_slist *chunk = NULL;
//
//    /* Remove a header curl would otherwise add by itself */
//   	chunk = curl_slist_append(chunk, requestToSend);
//
//    /* Modify a header curl otherwise adds differently */
// 	chunk = curl_slist_append(chunk, host);
//
//    /* Add a header with "blank" contents to the right of the colon. Note that
//       we're then using a semicolon in the string we pass to curl! */
// //   chunk = curl_slist_append(chunk, "X-silly-header;");
//
//    /* set our custom set of headers */
//    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
//
//    curl_easy_setopt(curl, CURLOPT_URL, bt_args->bt_info->announce);
//    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
//
//    res = curl_easy_perform(curl);
//    /* Check for errors */
//    if(res != CURLE_OK)
//      fprintf(stderr, "curl_easy_perform() failed: %s\n",
//              curl_easy_strerror(res));
//
//    /* always cleanup */
//    curl_easy_cleanup(curl);
//
//    /* free the custom headers */
//    curl_slist_free_all(chunk);
//  }

   /* struct hostent *he;
    struct in_addr **addr_list;

    if ((he = gethostbyname(new_announce)) == NULL) {
        return 1;
    }
    printf("Official name is: %s\n", he->h_name);
    puts("IP addresses: ");
    addr_list = (struct in_addr **) he->h_addr_list;
    int i;
    for (i = 0; addr_list[i] != NULL; i++) {
        printf("%s ", inet_ntoa(*addr_list[i]));
    }

    
    int sock;
    struct sockaddr_in servAddr;
    struct sockaddr_in fromAddr;
    int fromSize;
    int respStringLen;

    int portNum = 80;
    char data_recv[ECHOMAX];
	char *requestToSend;
    requestToSend = malloc(100);
    puts(url_encode(bt_args->bt_info->announce));
    sprintf(requestToSend, "%s?info_hash=%s\n&peer_id=%s\n&port=%s"
                    "\n&downloaded=0\n&left=0\n&event=started", bt_args->bt_info->announce,
            url_encode(hashed_info), url_encode(generate_peer_id()), url_encode(port));
    printf("\n%s \nto send \n", requestToSend);
*/
    /* Create a datagram/UDP socket */
/*    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        printf("fail create socket");
        exit(1);
    }
*/
//    memset(&servAddr, 0, sizeof(servAddr));    /* Zero out structure */
//   servAddr.sin_family = AF_INET;                 /* Internet addr family */
//    servAddr.sin_addr.s_addr = inet_addr(inet_ntoa(*addr_list[0]));
//    servAddr.sin_port = htons(portNum);     /* Server port */


    //send request to tracker server
/*    if (send(sock, requestToSend, strlen(requestToSend), 0) != strlen(requestToSend)) {
        printf("fail send \n");
        exit(1);
    }
*/
    /* Recv a response */
/*    fromSize = sizeof(fromAddr);
    if ((respStringLen = recvfrom(sock, data_recv, ECHOMAX, 0,
            (struct sockaddr *) &fromAddr, (socklen_t *) &fromSize)) != strlen(requestToSend)) {
        printf("fail to recv \n");
        exit(1);
    }
*/
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

void _fill_info(bt_info_t *info_t, be_node *node, ssize_t indent, char *key) {
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
            //            if (strcmp(key, ""))
            //                info_t->num_pieces  = node->val.i;
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
}

int parse_bt_info(bt_info_t *bt_info, be_node *node) {
    _fill_info(bt_info, node, 0, "");
    printf("announce ----- > %s \n", bt_info->announce);
    printf("name ----- > %s \n", bt_info->name);
    printf("length ----- > %d \n", bt_info->length);
    return 1;
}

