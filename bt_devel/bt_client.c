#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h> //ip hdeader library (must come before ip_icmp.h)
#include <netinet/ip_icmp.h> //icmp header
#include <arpa/inet.h> //internet address library
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>


#include "bencode.h"
#include "bt_lib.h"
#include "bt_setup.h"

void _int_handler(int);

int main(int argc, char *argv[])
{

    bt_args_t bt_args;
    be_node *node; // top node in the bencoding
    int i;

    parse_args(&bt_args, argc, argv);


    if (bt_args.verbose)
    {
        printf("Args:\n");
        printf("verbose: %d\n", bt_args.verbose);
        printf("save_file: %s\n", bt_args.save_file);
        printf("log_file: %s\n", bt_args.log_file);
        printf("torrent_file: %s\n", bt_args.torrent_file);

        for (i = 0; i < MAX_CONNECTIONS; i++)
        {
            if (bt_args.peers[i] != NULL)
                print_peer(bt_args.peers[i]);
        }


    }

    //read and parse the torent file
    node = load_be_node(bt_args.torrent_file);

    if (bt_args.verbose)
    {
        be_dump(node);
    }

    bt_info_t *info_t = malloc(sizeof(bt_info_t));
    parse_bt_info(info_t, node);
    bt_args.bt_info = info_t;

    if (contact_tracker(&bt_args))
        exit(EXIT_FAILURE);


    for (i = 0; i < MAX_CONNECTIONS; ++i)

        if (bt_args.peers[i])
        {
            bt_handshake_t handshake_t;

            handshake_t.protocol_name_length = 19;
            memcpy(handshake_t.protocol_name , "BitTorrent protocol", 19);
            memset(handshake_t.reserved_bytes, 0, 8);
            memcpy(handshake_t.hash_info, bt_args.info_hash , 20);
            memcpy(handshake_t.peer_id , bt_args.bt_peer_id, 20);
            puts("\n\n");
            handshake(bt_args.peers[i], handshake_t);
            //

        }

    // bt_msg_t msg;
    // msg.length = 1;
    // msg.type = BT_INTERESTED_T;

    // send_to_peer(bt_args.peers[i], &msg);
    //    peer_t *peer = bt_args.peers[0];
    //    bt_msg_t msg;
    //    msg.length = 13;
    //    msg.type = BT_REQUEST_T;
    //    msg.payload.request.index = 1;
    //    msg.payload.request.begin = 0;
    //    msg.payload.request.length = (8 * 2048);
    //    send_to_peer(peer, &msg);
    //
    //    FILE *save_file = create_file(&bt_args, "save.txt", "ab+");
    //    char str[] = "Bla";
    //
    //    fwrite(str , 1, sizeof(str) , save_file);

    signal(SIGINT, _int_handler);

    //main client loop
    printf("Starting Main Loop\n");
    while (1)
    {

        //try to accept incoming connection from new peer


        //poll current peers for incoming traffic
        //   write pieces to files
        //   udpdate peers choke or unchoke status
        //   responses to have/havenots/interested etc.

        //for peers that are not choked
        //   request pieaces from outcoming traffic

        //check livelenss of peers and replace dead (or useless) peers
        //with new potentially useful peers

        //update peers,

    }

    return 0;
}

void  _int_handler(int sig)
{
    char  c;

    signal(sig, SIG_IGN);
    printf("\nOUCH, did you hit Ctrl-C?\n"
           "Do you really want to quit? [y/n] ");
    c = getchar();
    if (c == 'y' || c == 'Y') {
        exit(0);
    }
    else
        signal(SIGINT, _int_handler);
}
