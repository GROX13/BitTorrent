#include <stdio.h>
#include <string.h>
#include "bencode.h"
#include <sys/stat.h>
#include "setup.h"

int main(int argc, char *argv[]) {
    bencode_t ben;


    char filename[1024];
    get_filename(argc, argv, filename);
  //  puts(filename);
    
    char * file; 
    long long leng;
    file = read_file(filename, &leng);
      
   //puts(file);


    bencode_t ben2;


    const char *ren;

    int len, ret;

    bencode_init(&ben, file, strlen(file));

    ret = bencode_dict_get_next(&ben, &ben2, &ren, &len);
    printf("foo %s %i\n", ren, len);
   // bencode_string_value(&ben2, &ren, &len);
    //printf("bla %s %i\n", ren, len);
   
    return 0;
}
