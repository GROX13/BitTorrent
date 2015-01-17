#include <stdio.h>
#include <string.h>
#include "bencode.h"
#include <sys/stat.h>

#include "setup.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <netinet/in.h>

#define ECHOMAX 255

void connect_to_tracker(int argc,  char *argv[]){
    char *requestToSend;
    int sock;
    struct sockaddr_in servAddr;
    struct sockaddr_in fromAddr;
    int fromSize;
    int respStringLen;

    int portNum =80;
    char data_recv[ECHOMAX];

    char *hash="12345678901234567890";
    char *id="ABCDEFGHIJKLMNOPQRST";
    char *temp;
    temp = "udp://tracker.thepiratebay.org??info_hash="
            "12345678901234567890\n&peer_id=ABCDEFGHIJKLMNOPQRST"
            "\nport=6888\n&downloaded=0\n&left=0\n&event=started";
    requestToSend = malloc(sizeof(temp)+1);
    // sprintf(requestToSend, "%s??info_hash=%s\n&peer_id=%s\nport=%s"
    //         "\n&downloaded=0\n&left=0\n&event=started\0","udp://tracker"
    //         ".thepiratebay.org", hash,id,"6888");
    sprintf(requestToSend, "%s??info_hash=%s\n&peer_id=%s\nport=%s"
            "\n&downloaded=0\n&left=0\n&event=started","udp://tracker"
            ".thepiratebay.org", hash,id,"6888");
    printf("%s to send \n",  requestToSend);

    /* Create a datagram/UDP socket */
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
        printf("fail create socket");
        exit(1);
    }

    struct hostent *hp = gethostbyname("tracker.thepiratebay.org");//
    if(!hp)
    {
        herror("gethostbyname(): ");
        exit(1);
    }
    /* Construct the server address structure */
    hp = gethostbyname("udp://tracker.thepiratebay.org");

    memset(&servAddr, 0, sizeof(servAddr));    /* Zero out structure */
    servAddr.sin_family = AF_INET;                 /* Internet addr family */
    memcpy( (char *) &servAddr.sin_addr.s_addr, hp->h_addr, hp->h_length );
    servAddr.sin_port   = htons(portNum);     /* Server port */


    //send request to tracker server 
    if (send(sock, requestToSend, strlen(requestToSend), 0) != strlen(requestToSend)){
        printf("fail send");
        exit(1);
    }

    /* Recv a response */
    fromSize = sizeof(fromAddr);
    if ((respStringLen = recvfrom(sock, data_recv, ECHOMAX, 0,
            (struct sockaddr *) &fromAddr, (socklen_t *) &fromSize)) != strlen(requestToSend)){
        printf("fail to recv");
        exit(1);
    }
}

void get_filename(int argc,  char *argv[], char filename[])
{
    if (argc != 2)
    {
        puts("Number of arguments must be 2");
        exit(1);
    }

    memset(filename, 0x00, 1024);
    strncpy(filename, argv[1], 1024);
}

char *read_file(char *file, long long *len)
{
    struct stat st;
    char *ret = NULL;
    FILE *fp;

    if (stat(file, &st))
    {
        return ret;
    }
    *len = st.st_size;

    fp = fopen(file, "r");
    if (!fp)
        return ret;

    ret = malloc(*len);
    if (!ret)
        return NULL;

    fread(ret, 1, *len, fp);

    fclose(fp);

    return ret;
}
