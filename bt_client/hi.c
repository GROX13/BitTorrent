char* send_http_request(char* url){
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
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&body);
	curl_easy_setopt(curl_handle, CURLOPT_HEADERDATA, (void *)&header);
	/* some servers don't like requests that are made without a user-agent
	 field, so we provide one */ 
	curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	/* get it! */ 
	res = curl_easy_perform(curl_handle);
	/* check for errors */ 
	if(res != CURLE_OK) {
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		return NULL;
	}else{
		if(memcmp(body.memory, "d8:", 3) != 0){
			printf("error\n%s\n", body.memory);
			return NULL;
		}else{
			return body.memory;
		}
	}
}
static size_t my_string_append(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct my_string *mem = (struct my_string *)userp;
 
  mem->memory = realloc(mem->memory, mem->size + realsize + 1);
 
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}


//    char *file;
//    long long leng;
//    file = read_file(bt_args->torrent_file, &leng);
//    puts(file);
//    printf("%i\n", (int) strlen(file));
//    puts(strstr(strstr(file, "info"), "d"));
//    char *hashed_info = malloc(21);
//    int len = (int) strlen(strstr(strstr(file, "info"), "d"));
//    printf("len is %i\n", len);
//    SHA1((unsigned char const *) strstr(strstr(file, "info"), "d"), (size_t) len, (unsigned char *) hashed_info);
//    puts(hashed_info);
//    puts(bt_args->bt_info->announce);
//
//    int announce_len = (int) strlen(bt_args->bt_info->announce);
//    char *announce = malloc((size_t) announce_len);
//    strcpy(announce, bt_args->bt_info->announce);
//    reverse(announce, 0, announce_len - 1);
//    char port[5];
//    int port_index = (int) strlen(strstr(announce, ":"));
//    strcpy(port, (char *) bt_args->bt_info->announce + port_index);
//    puts(port);
//    memset(announce, '\0', (size_t) announce_len);
//    strncpy(announce, bt_args->bt_info->announce, (size_t) (port_index - 1));
//
//    char *new_announce = malloc((size_t) announce_len);
//    memset(new_announce, '\0', (size_t) announce_len);
//    puts(strstr(announce, ":"));
//    strcpy(new_announce, (char *) strstr(announce, ":") + 3);
//
//    puts(new_announce);
//
//	char *requestToSend;
//    requestToSend = malloc(100);
//    puts(url_encode(bt_args->bt_info->announce));
//    sprintf(requestToSend, "GET /announce?info_hash=%s&peer_id=%s&port=%s"
//                    "&downloaded=0&left=0&event=started HTTP/1.0",
//            url_encode(hashed_info), url_encode(generate_peer_id()), url_encode(port));
//    printf("\n%s \nto send \n", requestToSend);
//
//	char *host;
//	host = malloc(strlen(new_announce)+6);
//	sprintf(host, "Host: %s", new_announce);

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