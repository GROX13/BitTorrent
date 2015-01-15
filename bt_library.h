#ifndef _BT_LIBRARY_H
#define _BT_LIBRARY_H

/*
 * Maximum file name size, to make things easy
 */

#define FILE_NAME_MAX 1024

/*
 * Maximum url size, to make things easy
 */

#define URL_NAME_MAX 2048


/*
 * initial port to try and open a listen socket on
 */

#define INIT_PORT 6881

/*
 * max port to try and open a listen socket on
 */

#define MAX_PORT 6889

/*
 * Different BitTorrent Message Types. The keep-alive
 * message isn't defined, because it is a message with
 * zero bytes, specified with the length prefix set to
 * zero. There is no message ID and no payload.
 */

#define CHOKE 0
#define UNCHOKE 1
#define INTERSTED 2
#define NOT_INTERESTED 3
#define HAVE 4
#define BITFILED 5
#define REQUEST 6
#define PIECE 7
#define CANCEL 8


#endif
