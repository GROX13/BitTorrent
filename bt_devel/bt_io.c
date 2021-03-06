#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <ctype.h>
#include <glob.h>
#include <assert.h>
#include <inttypes.h>
#include <fcntl.h>
#include <sys/types.h>
#include <inttypes.h>
#include <sys/stat.h>
#include "bt_setup.h"
#include "bt_lib.h"
#include "bencode.h"
#include "bt_io.h"

int create_file_descriptor(char *filename) {
    int file = 0;
    if ((file = open(filename, O_RDWR)) < -1)
        return 1;
    return file;
}

int save_data_to_file(void *ptr, size_t len, int index, int file_desc, char *filename) {

    struct stat st;
    stat(filename, &st);
    int size = st.st_size;

    char *before_index = malloc(index);
    if (read(file_desc, before_index, index) != index) return 1;

    if (lseek(file_desc, index, SEEK_SET) < 0) return 1;

    char *after_index = malloc(size - index);
    if (read(file_desc, after_index, (size - index)) != (size - index)) return 1;

    if (lseek(file_desc, 0, SEEK_SET) < 0) return 1;

    char *all = malloc(size + index);

    memcpy(all, before_index, index);
    memcpy((char *) all + index, ptr, len);
    memcpy((char *) all + index + len, after_index, (size - index));

    if (write(file_desc, all, strlen(all)) != strlen(all)) return 1;

    if (lseek(file_desc, 0, SEEK_SET) < 0) return 1;

    return 0;

}

int load_data_from_file(void *ptr, size_t len, int index, int file_desc, char *filename) {

    struct stat st;
    stat(filename, &st);
    int size = st.st_size;

    if (index >= size) return 1;

    if (lseek(file_desc, index, SEEK_SET) < 0) return 1;

    ptr = malloc(len);

    if (read(file_desc, ptr, len) != len) return 1;

    if (lseek(file_desc, 0, SEEK_SET) < 0) return 1;

    //puts(ptr);

    return 0;

}
