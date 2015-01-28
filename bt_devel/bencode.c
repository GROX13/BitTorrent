/*
 * C implementation of a bencode decoder.
 * This is the format defined by BitTorrent:
 *  http://wiki.theory.org/BitTorrentSpecification#bencoding
 *
 * The only external requirements are a few [standard] function calls and
 * the long long type.  Any sane system should provide all of these things.
 *
 * See the bencode.h header file for usage information.
 *
 * This is released into the public domain:
 *  http://en.wikipedia.org/wiki/Public_Domain
 *
 * Written by:
 *   Mike Frysinger <vapier@gmail.com>
 * And improvements from:
 *   Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>
 */

/*
 * This implementation isn't optimized at all as I wrote it to support a bogus
 * system.  I have no real interest in this format.  Feel free to send me
 * patches (so long as you don't copyright them and you release your changes
 * into the public domain as well).
 */

#include <stdlib.h> /* malloc() realloc() free() strtoll() */
#include <string.h> /* memset() */
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>

#include "bencode.h"

//allocates memory of the right size
be_node *be_alloc(be_type type)
{
	be_node *ret = malloc(sizeof(*ret));
	if (ret) {
		memset(ret, 0x00, sizeof(*ret));
		ret->type = type;
	}
	return ret;
}

//decodes an bencoded integer
 long long _be_decode_int(const char **data, long long *data_len)
{
	char *endp;
	long long ret = strtoll(*data, &endp, 10);
	*data_len -= (endp - *data);
	*data = endp;
	return ret;
}

//copies out the size of the string portion from the bencoding
long long be_str_len(be_node *node)
{
	long long ret = 0;
	if (node->val.s)
		memcpy(&ret, node->val.s - sizeof(ret), sizeof(ret));
	return ret;
}

//decodes a bencoded string
 char *_be_decode_str(const char **data, long long *data_len)
{
	long long sllen = _be_decode_int(data, data_len);
	long slen = sllen;
	unsigned long len;
	char *ret = NULL;

	/* slen is signed, so negative values get rejected */
	if (sllen < 0)
		return ret;

	/* reject attempts to allocate large values that overflow the
	 * size_t type which is used with malloc()
	 */
	if (sizeof(long long) != sizeof(long))
		if (sllen != slen)
			return ret;

	/* make sure we have enough data left */
	if (sllen > *data_len - 1)
		return ret;

	/* switch from signed to unsigned so we don't overflow below */
	len = slen;

	if (**data == ':') {
		char *_ret = malloc(sizeof(sllen) + len + 1);
		memcpy(_ret, &sllen, sizeof(sllen));
		ret = _ret + sizeof(sllen);
		memcpy(ret, *data + 1, len);
		ret[len] = '\0';
		*data += len + 1;
		*data_len -= len + 1;
	}
	return ret;
}

 be_node *_be_decode(const char **data, long long *data_len)
{
	be_node *ret = NULL;

	if (!*data_len)
		return ret;

	switch (**data) {
		/* lists */
		case 'l': {
			unsigned int i = 0;

			ret = be_alloc(BE_LIST);

			--(*data_len);
			++(*data);
			while (**data != 'e') {
				ret->val.l = realloc(ret->val.l, (i + 2) * sizeof(*ret->val.l));
				ret->val.l[i] = _be_decode(data, data_len);
				if (!ret->val.l[i])
					break;
				++i;
			}
			--(*data_len);
			++(*data);

			ret->val.l[i] = NULL;

			return ret;
		}

		/* dictionaries */
		case 'd': {
			unsigned int i = 0;

			ret = be_alloc(BE_DICT);

			--(*data_len);
			++(*data);
			while (**data != 'e') {
				ret->val.d = realloc(ret->val.d, (i + 2) * sizeof(*ret->val.d));
				ret->val.d[i].key = _be_decode_str(data, data_len);
				ret->val.d[i].val = _be_decode(data, data_len);
				if (!ret->val.l[i])
					break;
				++i;
			}
			--(*data_len);
			++(*data);

			ret->val.d[i].val = NULL;

			return ret;
		}

		/* integers */
		case 'i': {
			ret = be_alloc(BE_INT);

			--(*data_len);
			++(*data);
			ret->val.i = _be_decode_int(data, data_len);
			if (**data != 'e')
				return NULL;
			--(*data_len);
			++(*data);

			return ret;
		}

		/* byte strings */
		case '0'...'9': {
			ret = be_alloc(BE_STR);

			ret->val.s = _be_decode_str(data, data_len);

			return ret;
		}

		/* invalid */
		default:
			break;
	}

	return ret;
}

be_node *be_decoden(const char *data, long long len)
{
	return _be_decode(&data, &len);
}

be_node *be_decode(const char *data)
{
	return be_decoden(data, strlen(data));
}

 inline void _be_free_str(char *str)
{
	if (str)
		free(str - sizeof(long long));
}
void be_free(be_node *node)
{
	switch (node->type) {
		case BE_STR:
			_be_free_str(node->val.s);
			break;

		case BE_INT:
			break;

		case BE_LIST: {
			unsigned int i;
			for (i = 0; node->val.l[i]; ++i)
				be_free(node->val.l[i]);
			free(node->val.l);
			break;
		}

		case BE_DICT: {
			unsigned int i;
			for (i = 0; node->val.d[i].val; ++i) {
				_be_free_str(node->val.d[i].key);
				be_free(node->val.d[i].val);
			}
			free(node->val.d);
			break;
		}
	}
	free(node);
}



 void _be_dump_indent(ssize_t indent)
{
	while (indent-- > 0)
		printf("    ");
}
 void _be_dump(be_node *node, ssize_t indent)
{
	size_t i;

	_be_dump_indent(indent);
	indent = abs(indent);

	switch (node->type) {
		case BE_STR:
			printf("str = %s (len = %lli)\n", node->val.s, be_str_len(node));
			break;

		case BE_INT:
			printf("int = %lli\n", node->val.i);
			break;

		case BE_LIST:
			puts("list [");

			for (i = 0; node->val.l[i]; ++i)
				_be_dump(node->val.l[i], indent + 1);

			_be_dump_indent(indent);
			puts("]");
			break;

		case BE_DICT:
			puts("dict {");

			for (i = 0; node->val.d[i].val; ++i) {
				_be_dump_indent(indent + 1);
				printf("%s => ", node->val.d[i].key);
				_be_dump(node->val.d[i].val, -(indent + 1));
			}

			_be_dump_indent(indent);
			puts("}");
			break;
	}
}
void be_dump(be_node *node)
{
	_be_dump(node, 0);
}


char * _read_file(char * file, long long *len){
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

be_node * load_be_node(char * torf){
  char * torf_d; //stores the raw data of the torrent file
  long long torf_s;
  be_node * node; //store the top node in the bencoding of the torrent file
  torf_d = _read_file(torf,&torf_s);
  node = be_decoden(torf_d,torf_s);
  free(torf_d); //free the raw torrent file, not needed anymore

  return node;
}
