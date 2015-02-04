#ifndef _BT_IO_H
#define _BT_IO_H

FILE *create_file(bt_args_t *bt_args, char *filename, char *file_type);

int save_data_to_file(void *ptr, size_t len, int index, int file_desc, char* filename);

/*load a piece of the file into piece */
int load_data_from_file(bt_args_t *bt_args, bt_piece_t *piece);

#endif
