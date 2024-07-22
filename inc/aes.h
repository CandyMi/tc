/*
** Advanced Encryption Standard **
*/
#ifndef __TC_AES__
#define __TC_AES__

#define AES_MAXNR       (14)
#define AES_BLOCK_SIZE  (16)

#define AES_ENCRYPT     (1)
#define AES_DECRYPT     (0)

typedef struct tc_aes_key
{
  uint32_t rd_key[4 * (AES_MAXNR + 1)];
  int32_t  rounds;
} AES_KEY;

typedef enum tc_aes_bit_t {
#define AES_128 aes_128
  aes_128 = 128,
#define AES_192 aes_192
  aes_192 = 192,
#define AES_256 aes_256
  aes_256 = 256,
} aes_bit_t;

TC_EXPORT int AES_set_encrypt_key(const uint8_t *userKey, const aes_bit_t bits, AES_KEY *key);

TC_EXPORT int AES_set_decrypt_key(const uint8_t *userKey, const aes_bit_t bits, AES_KEY *key);

TC_EXPORT void AES_encrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);

TC_EXPORT void AES_decrypt(const uint8_t *in, uint8_t *out, const AES_KEY *key);

#endif