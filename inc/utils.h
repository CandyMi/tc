#ifndef __TC_UTILS__
#define __TC_UTILS__

/*
** crc-32 **
*/

#define crc32 crc32
TC_EXPORT unsigned int crc32(const void *text, unsigned int tsize);

/*
** adler-32 **
*/

#define adler32 adler32
TC_EXPORT unsigned int adler32(const void *text, unsigned int tsize);

/*
** HEX **
*/

enum tc_hex_t {
#define tc_hex_lower tc_hex_lower
  tc_hex_lower = 0, // lower case
#define tc_hex_upper tc_hex_upper
  tc_hex_upper = 1, // upper case
};

/* Calculate the `encode` buffer length */
#define HEX_ENC_LENGTH(len) ((len << 1) + 1)
/* Calculate the `decode` buffer length */
#define HEX_DEC_LENGTH(len) ((len >> 1) + 1)

/* hexencode `md` is tsize * 2 */
#define hexencode hexencode
TC_EXPORT int hexencode(const void* text, unsigned int tsize, unsigned char *md, int mode);
/* hexdecode `md` is tsize / 2 */
#define hexdecode hexdecode
TC_EXPORT int hexdecode(const void* text, unsigned int  tsize, unsigned char *md);

/*
** URL **
*/

/* Calculate the `encode` buffer length */
#define URL_ENC_LENGTH(len) ((len * 3) + 1)
/* Calculate the `decode` buffer length */
#define URL_DEC_LENGTH(len) ((len) + 1)

#define urlencode urlencode
TC_EXPORT int urlencode(const void *text, unsigned int tsize, unsigned char *md);
#define urldecode urldecode
TC_EXPORT int urldecode(const void *text, unsigned int tsize, unsigned char *md);

/*
** BASE64 **
*/

enum tc_b64_t {
#define tc_b64_non tc_b64_non
  tc_b64_non       = 0,
#define tc_b64_url tc_b64_url
  tc_b64_url       = 1,
#define tc_b64_nopadding tc_b64_nopadding
  tc_b64_nopadding = 2,
};

/* Calculate the `encode` buffer length */
#define BASE64_ENC_LENGTH(len) ((((len) + 2) / 3 * 4) + 1)
/* Calculate the `decode` buffer length */
#define BASE64_DEC_LENGTH(len) (((len + 3) / 4 * 3) + 1)

#define base64encode base64encode
TC_EXPORT int base64encode(const void* text, unsigned int tsize, unsigned char *md, int mode);

#define base64decode base64decode
TC_EXPORT int base64decode(const void* text, unsigned int tsize, unsigned char *md, int mode);

/*
** Random key **
*/

#define RKEY_MIN_LENGTH  (8)
#define UUID_V4_LENGTH   (36)

#define uuid_v4 tc_uuid_v4
TC_EXPORT int tc_uuid_v4(unsigned char *ubuf);

#define randomkey tc_randomkey
TC_EXPORT int tc_randomkey(unsigned char *rbuf, unsigned int rsize);

/*
**  Hash
*/
#define HASHKEY_LENGTH      (8)
#define HASHXOR_LENGTH(len) (len)

#define hashkey hashkey
TC_EXPORT int hashkey(const void* text, unsigned int tsize, unsigned char md[HASHKEY_LENGTH]);

#define hashxor hashxor
TC_EXPORT int hashxor(const void* key, unsigned int ksize, const void* text, unsigned int tsize, unsigned char* md);

#endif