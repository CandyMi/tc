#ifndef __TC_UTILS__
#define __TC_UTILS__


/*
** Random **
*/

#define tc_random_next tc_random_next
TC_EXPORT int tc_random_next();

#define tc_randomkey tc_randomkey
TC_EXPORT int tc_randomkey(unsigned char *rbuf, unsigned int rsize);

/*
** CurrentTime **
*/

#ifdef _WIN32
  #define tc_time_t     time_t
  #define tc_longtime_t unsigned long long
#else
  #define tc_time_t     time_t
  #define tc_longtime_t unsigned long
#endif

TC_EXPORT int tc_time(tc_time_t *ts);
TC_EXPORT int tc_time_millisecond(tc_longtime_t *ts);
TC_EXPORT int tc_time_microsecond(tc_longtime_t *ts);

/*
** crc-32 **
*/

#define crc32 tc_crc32
TC_EXPORT unsigned int tc_crc32(const void *text, unsigned int tsize);

/*
** adler-32 **
*/

#define adler32 tc_adler32
TC_EXPORT unsigned int tc_adler32(const void *text, unsigned int tsize);

/*
** HEX **
*/

typedef enum tc_hex_t {
#define tc_hex_lower tc_hex_lower
  tc_hex_lower = 0, // lower case
#define tc_hex_upper tc_hex_upper
  tc_hex_upper = 1, // upper case
} tc_hex_t;

/* Calculate the `encode` buffer length */
#define HEX_ENC_LENGTH(len) ((len << 1) + 1)
/* Calculate the `decode` buffer length */
#define HEX_DEC_LENGTH(len) ((len >> 1) + 1)

/* hexencode `md` is tsize * 2 */
#define hexencode tc_hexencode
TC_EXPORT int tc_hexencode(const void* text, unsigned int tsize, unsigned char *md, tc_hex_t mode);
/* hexdecode `md` is tsize / 2 */
#define hexdecode tc_hexdecode
TC_EXPORT int tc_hexdecode(const void* text, unsigned int  tsize, unsigned char *md);

/*
** URL **
*/

/* Calculate the `encode` buffer length */
#define URL_ENC_LENGTH(len) ((len * 3) + 1)
/* Calculate the `decode` buffer length */
#define URL_DEC_LENGTH(len) ((len) + 1)

#define urlencode tc_urlencode
TC_EXPORT int tc_urlencode(const void *text, unsigned int tsize, unsigned char *md);
#define urldecode tc_urldecode
TC_EXPORT int tc_urldecode(const void *text, unsigned int tsize, unsigned char *md);

/*
** BASE64 **
*/

typedef enum tc_b64_t {
#define tc_b64_non tc_b64_non
  tc_b64_non       = 0,
#define tc_b64_url tc_b64_url
  tc_b64_url       = 1,
#define tc_b64_nopadding tc_b64_nopadding
  tc_b64_nopadding = 2,
} tc_b64_t;

/* Calculate the `encode` buffer length */
#define BASE64_ENC_LENGTH(len) ((((len) + 2) / 3 * 4) + 1)
/* Calculate the `decode` buffer length */
#define BASE64_DEC_LENGTH(len) (((len + 3) / 4 * 3) + 1)

#define base64encode tc_base64encode
TC_EXPORT int tc_base64encode(const void* text, unsigned int tsize, unsigned char *md, tc_b64_t mode);

#define base64decode tc_base64decode
TC_EXPORT int tc_base64decode(const void* text, unsigned int tsize, unsigned char *md, tc_b64_t mode);

/*
** Random key **
*/

#define RKEY_MIN_LENGTH  (8)
#define UUID_V4_LENGTH   (36)

#define uuid_v4 tc_uuid_v4
TC_EXPORT int tc_uuid_v4(unsigned char *ubuf);

#define ulid tc_ulid
TC_EXPORT int tc_ulid(unsigned char ulid[26]);

#define randomkey tc_randomkey
TC_EXPORT int tc_randomkey(unsigned char *rbuf, unsigned int rsize);

#define nanoid tc_nanoid
TC_EXPORT int tc_nanoid(const char *alphabet, unsigned char *rbuf, unsigned int *rsize);
/*
**  Hash
*/

#define HASHKEY_LENGTH      (8)
#define HASHKEY64_LENGTH    (16)
#define HASHXOR_LENGTH(len) (len)

#define hashkey tc_hashkey
TC_EXPORT int tc_hashkey(const void* text, unsigned int tsize, unsigned char md[HASHKEY_LENGTH]);

#define tc_hashkey64 tc_hashkey64
TC_EXPORT int tc_hashkey64(const void* text, unsigned int tsize, unsigned char md[HASHKEY_LENGTH]);

#define hashxor tc_hashxor
TC_EXPORT int tc_hashxor(const void* key, unsigned int ksize, const void* text, unsigned int tsize, unsigned char* md);

/*
**  PBKDF2
*/

typedef enum tc_sign_method_t{
#define TC_MD5 tc_sign_md5
  tc_sign_md5    = 1,
#define TC_SHA128 tc_sign_sha128
  tc_sign_sha128 = 2,
#define TC_SHA256 tc_sign_sha256
  tc_sign_sha256 = 3,
} tc_sign_method_t;

TC_EXPORT int tc_pbkdf2(tc_sign_method_t mode, const void* password, unsigned int plen, const void* salt, unsigned int slen, unsigned int count, unsigned char* out);

#endif