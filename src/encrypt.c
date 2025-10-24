#include <stdio.h>
#include <string.h>

int
XOR (void *data, int size)
{
  if (data == NULL || size < 0)
    {
      return -1;
    }
  for (int i = 0; i != size; i++)
    {
      ((char *)data)[i] ^= 0xAA;
    }
  return 0;
}

char
Base64Sym (char num)
{
  if (num >= 0 && num <= 25)
    {
      return num + 65;
    }
  else if (num >= 26 && num <= 51)
    {
      return num - 26 + 97;
    }
  else if (num >= 52 && num <= 61)
    {
      return num - 52 + 48;
    }
  else if (num == 62)
    {
      return 43;
    }
  else if (num == 63)
    {
      return 47;
    }
  return -1;
}
int
Base64Num (unsigned char sym, unsigned char *num)
{
  if (sym >= 65 && sym <= 90)
    {
      *num = sym - 65;
    }
  else if (sym >= 97 && sym <= 122)
    {
      *num = sym - 97 + 26;
    }
  else if (sym >= 48 && sym <= 57)
    {
      *num = sym - 48 + 52;
    }
  else if (sym == 43)
    {
      *num = 62;
    }
  else if (sym == 47)
    {
      *num = 63;
    }
  else
    {
      return -1;
    }
  return 0;
}

int
Base64 (const void *data, int size, char *dst_str, int size_dst_str)
{
  if (data == NULL || size < 0)
    {
      return -1;
    }
  if (size < 0 || size_dst_str < 0)
    {
      return -1;
    }
  /*
  (size / 3) * 4 - count 6bit symbols in packs 3 byte
  size % 3 + 1 - count symbols after 3 byte packs
  (size % 3 == 0)?0:3-size%3) count symbol =
  1 - '\0'
  */
  int needed_size = (size / 3) * 4 + size % 3 + 1
                    + ((size % 3 == 0) ? 0 : 3 - size % 3) + 1;
  if (size_dst_str < (needed_size))
    {
      return -1;
    }
  int pos = 0;

  /*3 bytes packs*/
  unsigned char *byte_p = NULL;
  for (int i = 0; i != size / 3; i++)
    {
      unsigned int block = 0;
      byte_p = (unsigned char *)data + i * 3;
      block = *byte_p << 16 | *(byte_p + 1) << 8 | *(byte_p + 2);
      dst_str[pos++] = Base64Sym ((block >> 18) & 0x3F);
      dst_str[pos++] = Base64Sym ((block >> 12) & 0x3F);
      dst_str[pos++] = Base64Sym ((block >> 6) & 0x3F);
      dst_str[pos++] = Base64Sym (block & 0x3F);
    }
  char last_bytes_count = size % 3;

  unsigned char *byte = (unsigned char *)data + (size / 3) * 3;
  /*bytes after 3 bytes packs*/
  unsigned int block = 0;
  for (int i = 0; i != last_bytes_count; i++)
    {
      block = (block << 8) | (*(byte + i));
    }
  char eq_count = 0;
  if (last_bytes_count == 1)
    {
      block <<= 4;
      dst_str[pos++] = Base64Sym ((block >> 6) & 0x3F);
      dst_str[pos++] = Base64Sym (block & 0x3F);
      eq_count = 2;
    }
  else if (last_bytes_count == 2)
    {
      block <<= 2;
      dst_str[pos++] = Base64Sym ((block >> 12) & 0x3F);
      dst_str[pos++] = Base64Sym ((block >> 6) & 0x3F);
      dst_str[pos++] = Base64Sym (block & 0x3F);
      eq_count = 1;
    }

  for (int i = 0; i != eq_count; i++)
    {
      dst_str[pos++] = '=';
    }

  dst_str[pos] = '\0';
  return 0;
}

int
Base64Decode (const unsigned char *src_str, size_t size_src,
              unsigned char *const dst_str, size_t size_dst_str)
{
  if (src_str == NULL || dst_str == NULL)
    {
      return -1;
    }
  if (size_src % 4 != 0)
    { /*кол-во эл. в Base64 всегда кратно 4*/
      return -1;
    }
  if (size_dst_str < (size_src * 3) / 4)
    {
      return -1;
    }
  int pos = 0;
  const unsigned char *byte_p = NULL;
  for (size_t i = 0; i != (size_src / 4) - 1; i++)
    {
      byte_p = src_str + i * 4;
      unsigned int block = 0;
      unsigned char character = 0;
      for (int j = 0; j != 4; j++)
        {
          if (Base64Num (*(byte_p + j), &character))
            {
              return -1;
            }
          block = (block << 6) | character;
        }
      dst_str[pos++] = block >> 16 & 0xFF;
      dst_str[pos++] = block >> 8 & 0xFF;
      dst_str[pos++] = block & 0xFF;
    }
  const unsigned char *last_bytes_p = &src_str[((size_src / 4) - 1) * 4];
  int eq_count = 0;
  if (*(last_bytes_p + 2) == '=' && *(last_bytes_p + 3) == '=')
    {
      eq_count = 2;
    }
  else if (*(last_bytes_p + 2) != '=' && *(last_bytes_p + 3) == '=')
    {
      eq_count = 1;
    }

  unsigned int block = 0;
  unsigned char character = 0;

  for (int i = 0; i != 4 - eq_count; i++)
    {
      if (Base64Num (*(last_bytes_p + i), &character))
        {
          return -1;
        }
      block = (block << 6) | character;
    }
  block >>= eq_count * 2;
  if (eq_count == 1)
    {
      dst_str[pos++] = (block >> 8) & 0xFF;
      dst_str[pos++] = (block) & 0xFF;
    }
  else if (eq_count == 2)
    {
      dst_str[pos++] = block & 0xFF;
    }
  else if (eq_count == 0)
    {
      dst_str[pos++] = block >> 16 & 0xFF;
      dst_str[pos++] = block >> 8 & 0xFF;
      dst_str[pos++] = block & 0xFF;
    }
  dst_str[pos] = '\0';
  return 0;
}

int
Encrypt (void *src_data, size_t size_src, void *dst_data, size_t size_dst)
{
  if (XOR (src_data, size_src))
    {
      return -1;
    }
  if (Base64 (src_data, size_src, dst_data, size_dst))
    {
      return -1;
    }
  if (XOR (src_data, size_src))
    {
      return -1;
    }
  return 0;
}

int
Decrypt (void *src_data, size_t size_src, void *dst_data, size_t size_dst)
{
  if (Base64Decode ((unsigned char *)src_data, size_src,
                    (unsigned char *)dst_data, size_dst))
    {
      return -1;
    }
  if (XOR (dst_data, strlen (dst_data)))
    {
      return -1;
    }
  return 0;
}
