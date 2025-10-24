#ifndef ENRYPT_H
#define ENRYPT_H

#include <stddef.h>

int Decrypt (void *src_data, size_t size_src, void *dst_data, size_t size_dst);
int Encrypt (void *src_data, size_t size_src, void *dst_data, size_t size_dst);

#endif