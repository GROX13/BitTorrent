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
