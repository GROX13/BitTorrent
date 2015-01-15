#include <stdio.h>
#include <string.h>
#include "bencode.h"

int main(int argc, char *argv[]) {
    bencode_t ben;

    char *str = strdup("4:test");

    const char *ren;

    int len;

    bencode_init(&ben, str, strlen(str));
    printf("%i\n", ben.len);
    printf("%i\n", ben.val);
    puts(ben.start);
    puts(ben.str);
    bencode_string_value(&ben, &ren, &len);
    puts(ren);
    return 0;
}
