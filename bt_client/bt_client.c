#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "setup.h"
#include "bt_library.h"
#include "bt_bencode.h"

int main(int argc, char *argv[])
{
    be_node *node; // top node in the bencoding
    // connect_to_tracker(argc, argv);
    //    bencode_t ben;
    //
    //
    char filename[1024];
    get_filename(argc, argv, filename);
    puts(filename);
    //
    //    char *file;
    // long long leng;
    // file = read_file(filename, &leng);
    node = load_be_node(filename);
    puts("done");
    be_dump(node);

    bt_info_t *bt_info  = malloc(sizeof(bt_info_t));
    parse_bt_info(bt_info, node);
    puts("All Done");
    //
    //    //puts(file);
    //
    //
    //    bencode_t ben2;
    //
    //
    //    const char *ren;
    //
    //    int len, ret;
    //
    //    // bencode_init(&ben, file, strlen(file));
    //
    //    // ret = bencode_dict_get_next(&ben, &ben2, &ren, &len);
    //    // printf("foo %s %i\n", ren, len);
    //    // bencode_string_value(&ben2, &ren, &len);
    //    //printf("bla %s %i\n", ren, len);

    return 0;
}
