#include <stdio.h>
#include <string.h>
#include "bencode.h"
#include <sys/stat.h>

#include "setup.h"

void get_filename(int argc,  char * argv[], char filename[]){
    if(argc != 2){
        puts("Number of arguments must be 2");   
        exit(1); 
    }
    
    memset(filename,0x00,1024);
    strncpy(filename,argv[1],1024);
}

char * read_file(char * file, long long *len){
  struct stat st;
  char *ret = NULL;
  FILE *fp;
  
  if (stat(file, &st)){
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
