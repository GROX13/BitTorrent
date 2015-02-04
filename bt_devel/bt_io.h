#ifndef _BT_IO_H
#define _BT_IO_H

int create_file_descriptor(char *filename);

int save_data_to_file(void *ptr, size_t len, int index, int file_desc, char* filename);

int load_data_from_file(void *ptr, size_t len, int index, int file_desc, char* filename);

#endif
