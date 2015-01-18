#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "bt_setup.h"
#include "bt_library.h"
#include "bt_bencode.h"

static int create_socket()
{
    struct addrinfo adr_info, * result, * result_ptr;
    int sock, socket_fd = -1;
    memset(&adr_info, 0, sizeof(struct addrinfo));
    adr_info.ai_family = AF_UNSPEC;
    adr_info.ai_socktype = SOCK_STREAM;
    adr_info.ai_flags = AI_PASSIVE;

    sock = getaddrinfo(NULL, "80", &adr_info, &result);
    if (sock != 0)
    {
        perror("Error while geting address info");
        return -1;
    }

    for (result_ptr = result; result_ptr != NULL; result_ptr = result_ptr->ai_next)
    {
        socket_fd = socket(result_ptr->ai_family, result_ptr->ai_socktype, result_ptr->ai_protocol);
        if (socket_fd == -1)
            continue;

        sock = bind(socket_fd, result_ptr->ai_addr, result_ptr->ai_addrlen);
        if (sock == 0)
            break;
        close(socket_fd);
    }

    freeaddrinfo(result);

    if (result_ptr == NULL)
    {
        perror("Error while bind");
        close(socket_fd);
        return -1;
    }

    return socket_fd;
}

int main(int argc, char *argv[])
{
    be_node *node; // top node in the bencoding
    // connect_to_tracker(argc, argv);
    //    bencode_t ben;
    //
    //
    char filename[1024];
    get_filename(argc, argv, filename);
    puts(filename);
    //
    //    char *file;
    // long long leng;
    // file = read_file(filename, &leng);
    node = load_be_node(filename);
    puts("done");
    be_dump(node);

    bt_info_t *bt_info  = malloc(sizeof(bt_info_t));
    parse_bt_info(bt_info, node);
    puts("All Done");

    int i;
    struct hostent *he;
    struct in_addr **addr_list;

    if (argc != 2) {
        fprintf(stderr,"usage: ghbn hostname\n");
        return 1;
    }

    if ((he = gethostbyname("google.ge")) == NULL) {  // get the host info
        herror("gethostbyname");
        return 2;
    }

    // print information about this host:
    printf("Official name is: %s\n", he->h_name);
    printf("    IP addresses: ");
    addr_list = (struct in_addr **)he->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++) {
        printf("%s ", inet_ntoa(*addr_list[i]));
    }
    printf("\n");

    //    char *address;
    //    address = inet_ntoa(pHostInfo->h_addr);

    //
    //    //puts(file);
    //
    //
    //    bencode_t ben2;
    //
    //
    //    const char *ren;
    //
    //    int len, ret;
    //
    //    // bencode_init(&ben, file, strlen(file));
    //
    //    // ret = bencode_dict_get_next(&ben, &ben2, &ren, &len);
    //    // printf("foo %s %i\n", ren, len);
    //    // bencode_string_value(&ben2, &ren, &len);
    //    //printf("bla %s %i\n", ren, len);

    return 0;
}
