#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>


int create_socket (struct sockaddr_in sockaddr)
{
    int socket_desc;
    struct sockaddr_in server;

    //Create socket
    socket_desc = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_desc == -1) {
        puts("Could not create socket.");
        return -1;
    }

    //Connect to remote server
    if (connect(socket_desc, (struct sockaddr *) &sockaddr, sizeof(server)) < 0)
    {
        puts("Could not connect.");
        return -1;
    }

    return socket_desc;
}

int close_socket(int sock_fd) {
    if (close(sock_fd) < 0) {
        perror("Error on closing");
        return -1;
    }
    return 1;
}
