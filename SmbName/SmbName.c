/*
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation; either version 2 of
 *   the License or (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 *   USA
 */

/* NOTE:
 * Compile this program using only GCC and no other compilers
 * (except if you think this one supports the __attribute__ (( packed )) attribute)
 * This program might not work on big-endian systems.
 * It has been successfully tested from the following plateforms:
 * 	- Linux 2.4.18 / i686
 * 	- FreeBSD 4.6.1-RELEASE-p10 / i386
 * Don't bother me if you can't get it to compile or work on Solaris using the SunWS compiler.
 *
 * Another thing: The word counts are hardcoded, careful if you hack the sources.
 */

/* Copyright notice:
 * some parts of this source (only two functions, name_len and name_mangle)
 * has been taken from libsmb.  The rest, especially the structures has
 * been written by me.
 */
#define INCL_DOSPROCESS
#include <os2.h>

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include <types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <net\if.h>
#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
#include <arpa\inet.h>
#include <unistd.h>
#endif

#define uint32_t unsigned long
#define uint16_t unsigned short
#define uint8_t  unsigned char

#ifndef TCPV40HDRS   // Исключить для TCP/IP 4.0
#define myFD_SET(fd, set) { \
    if (((fd_set *)(set))->fd_count < FD_SETSIZE) \
        ((fd_set *)(set))->fd_array[((fd_set *)(set))->fd_count++]=fd; }
#else
#define myFD_SET(fd, set) { FD_SET(fd, set); }
#endif

#define bswap16(x) \
	((((x) >> 8) & 0xff) | (((x) & 0xff) << 8))

#pragma pack(1)
typedef struct
{ unsigned char server_component[4];
  unsigned char command;
  unsigned char error_class;
  unsigned char reserved1;
  uint16_t error_code;
  uint8_t flags;
  uint16_t flags2;
  unsigned char reserved2[12];
  uint16_t tree_id;
  uint16_t proc_id;
  uint16_t user_id;
  uint16_t mpex_id;
} smb_header;
#pragma pack()

#define bufsize 1024
#define netbios_ns_port 137

const unsigned char *global_scope = NULL;

/****************************************************************************
 * return the total storage length of a mangled name - from smbclient
 ****************************************************************************/
int name_len (char *s1)
{
  // NOTE: this argument _must_ be unsigned
  unsigned char *s = (unsigned char *) s1;
  int len;

  // If the two high bits of the byte are set, return 2.
  if (0xC0 == (*s & 0xC0)) return (2);

  /* Add up the length bytes. */
  for (len = 1; (*s); s += (*s) + 1) len += *s + 1;

  return (len);  // name_len
}

/****************************************************************************
 * mangle a name into netbios format - from smbclient
 *  Note:  <Out> must be (33 + strlen(scope) + 2) bytes long, at minimum.
 ****************************************************************************/
int name_mangle (char *In, char *Out, char name_type)
{
  int i, c, len;
  char buf[20], *p = Out;

  // Safely copy the input string, In, into buf[].
  (void) memset (buf, 0, 20);
  if (strcmp (In, "*") == 0) buf[0] = '*';
  else (void) sprintf (buf, "%-15.15s%c", In, name_type);

  // Place the length of the first field into the output buffer.
  p[0] = 32;
  p++;

  // Now convert the name to the rfc1001/1002 format.
  for (i = 0; i < 16; i++)
    {
    c = toupper (buf[i]);
    p[i * 2] = ((c >> 4) & 0x000F) + 'A';
    p[(i * 2) + 1] = (c & 0x000F) + 'A';
    }
  p += 32;
  p[0] = '\0';

  // Add the scope string.
  for (i = 0, len = 0; NULL != global_scope; i++, len++)
    {
    switch (global_scope[i])
      {
      case '\0':
        p[0] = len;
        if (len > 0) p[len + 1] = 0;
        return (name_len (Out));
      case '.':
        p[0] = len;
        p += (len + 1);
        len = -1;
        break;
      default:
        p[len + 1] = global_scope[i];
        break;
      }
    }
  return (name_len (Out));
}

#pragma pack(1)
typedef struct
{ uint16_t transaction_id;
  uint16_t flags;
  uint16_t questions;
  uint16_t answerRRs;
  uint16_t authorityRRs;
  uint16_t additionalRRs;
  unsigned char query[32];
  uint16_t name;
  uint16_t type;
  uint16_t class;
} nbt_name_query;
#pragma pack()

#pragma pack(1)
typedef struct
{ nbt_name_query answer;
  uint32_t ttl;
  uint16_t datalen;
  uint8_t names;
} nbt_name_query_answer;
#pragma pack()

char *
list_netbios_names (int fd, unsigned char *buffer, size_t size,
                    char *rhost, unsigned int timeout)
{
  nbt_name_query query;
  struct sockaddr_in dest;
  int i, len;

  fd_set rfds;
  struct timeval tv;

  memset (&dest, 0, sizeof (struct sockaddr_in));

  if ( (dest.sin_addr.s_addr = inet_addr(rhost)) == INADDR_NONE ) return NULL;
  dest.sin_family = AF_INET;
  dest.sin_port = htons(netbios_ns_port);

  memset (&query, 0, sizeof (nbt_name_query));

  query.transaction_id = (uint16_t) bswap16 (0x1e);
  query.flags = bswap16 (0x0010);
  query.questions = bswap16 (1);

  name_mangle ("*", query.query, 0);
  query.type = bswap16 (0x21);
  query.class = bswap16 (0x01);

  if ( sendto(fd, (char *)&query, sizeof (nbt_name_query), 0,
              (struct sockaddr *) &dest, sizeof (struct sockaddr_in)) !=
       sizeof (nbt_name_query) ) return NULL;

  // Now, wait for an answer - add a timeout to 10 seconds
  FD_ZERO (&rfds);
  myFD_SET (fd, &rfds);

  tv.tv_sec = 0;
  tv.tv_usec = timeout*1000; // единица измерения - микросекунда

  if (select (fd + 1, &rfds, NULL, NULL, &tv) <= 0) return NULL;

  len = recvfrom (fd, buffer, size, 0, NULL, NULL);

  for (i = 0; i < ((nbt_name_query_answer *) buffer)->names; i++)
    if ( (uint8_t) * (buffer + sizeof (nbt_name_query_answer) + 18 * i + 15) ==
         0x20 ) return buffer + sizeof (nbt_name_query_answer) + 18 * i;

  if ( len < 57 ) return NULL;
  return buffer+57;
}

void extract_name (const char *name, char *p)
{
  int i;

  for (i = 0; i < 14; i++) if (name[i] == ' ') break;
  else p[i] = name[i];

  p[i] = '\0';
}

void SmbName(char *NetBiosName, char *hostname, long udp_timeout)
{
  int fd, i;
  unsigned char *buffer, *name = NULL;

  if ( (buffer=calloc(bufsize, 1)) == NULL ) return;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  name = list_netbios_names(fd, buffer, bufsize, hostname, udp_timeout);
  soclose(fd);

  free(buffer);

  if ( name == NULL ) return;

  extract_name (name, NetBiosName);
}