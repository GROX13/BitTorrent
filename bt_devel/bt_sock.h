#ifndef _BT_SOCK_H
#define _BT_SOCK_H

#include <netinet/in.h>
#include <stdio.h>

/**
* create_socket(sockaddr_in sockaddr) -> int
*
* creates socket using structure sockaddr
* and returns socket file descriptor
*
* Returns negative number on error
*/
int create_socket(struct sockaddr_in sockaddr);

/**
* close_socket(int sock_fd) -> int
*
* closes socket, returns 1 on success.
* On error, -1 is returned
*
* Returns 1 on success, -1 on error
*/
int close_socket(int sock_fd);

#endif