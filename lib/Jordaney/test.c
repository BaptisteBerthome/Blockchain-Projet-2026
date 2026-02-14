//
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include "test.h"
#include "base58-code-decode.h"

#define nullptr NULL

void hex_string2int_array(byte * hex_string,uint8_t tab[33]){
  char sub[3];
  int j = 0; // for int tab
  for (int i = 0 ;i<65;i=i+2){
    // Extract substring of length 2 using strncpy
    strncpy(sub,(char *)hex_string + i, 2);
    sub[2] = '\0'; // Null terminate the substring
    tab[j] = (int)strtol(sub, NULL, 16); // convert ascii hex to binary
    j++;
  }
}

void printShaHex(const char * msg,byte *digest,int len){
  printf("%s",msg);
  for (uint32_t i = 0; i < len; i++)
      printf("%02x", digest[i]);
  printf("\n");
}

void calc_address(char address[],char * pub_key_char){
  unsigned char rmd[5 + RIPEMD160_DIGEST_LENGTH];
  uint8_t pub_key_int[33] = {0};
  hex_string2int_array(pub_key_char,pub_key_int);
  rmd[0] = 0; // adresse réseau

  RIPEMD160(SHA256((byte *)pub_key_int, 33, 0), SHA256_DIGEST_LENGTH, rmd + 1);
  memcpy(rmd + 21, SHA256(SHA256(rmd, 21, 0), SHA256_DIGEST_LENGTH, 0), 4);
  base58_encode(rmd, 25, address, 34);

  /* Count the number of 1s at the beginning of the address */
  int n = 0;
  for (n = 0; address[n] == '1'; n++);

  /* Do we need to remove any 1s? */
  if (n > 1) {
/* Move the memory so that the address begins at the final 1 */
      memmove(address, address + (n-1), 34-(n-1));

      /* Force the address to finish at the correct length */
      address[34-(n-1)] = '\0';
  }
    //printf("Address: %s\n\n", address);
}

int main()
{
    EC_KEY         *key_pair_obj = nullptr;
    int             ret_error;
    BIGNUM         *priv_key;
    EC_POINT       *pub_key;
    EC_GROUP       *secp256k1_group;
    char           *pub_key_char, *priv_key_char;
    char            address[34];
    const char     *message = "message to sign";
    unsigned char   buffer_digest[SHA256_DIGEST_LENGTH];
    uint8_t        *digest;
    uint8_t        *signature;
    uint32_t        signature_len;
    int             verification;

    BIGNUM          *bn;
    EC_KEY          *imported_key_pair = nullptr;
    EC_GROUP        *curve_group;
    EC_POINT        *public_point;
    int              char_read;

    // Generate secp256k1 key pair
    key_pair_obj = EC_KEY_new_by_curve_name(NID_secp256k1);
    ret_error    = EC_KEY_generate_key(key_pair_obj);

    // Get private key
    priv_key      = (BIGNUM *)EC_KEY_get0_private_key(key_pair_obj);
    priv_key_char = BN_bn2hex(priv_key);

    // Get public key
    pub_key         = (EC_POINT *)EC_KEY_get0_public_key(key_pair_obj);
    secp256k1_group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    pub_key_char    = EC_POINT_point2hex(secp256k1_group, pub_key, POINT_CONVERSION_COMPRESSED, nullptr);
    EC_GROUP_free(secp256k1_group);

    printf("Private key (HEX)            : %s, long = %lu\n", priv_key_char,strlen(priv_key_char));
    printf("Public key (HEX, compressed) : %s, long = %lu\n", pub_key_char,strlen(pub_key_char)); // compressée
    calc_address(address,pub_key_char);
    printf("Adresse P2PKH                : %s, long = %lu\n",address,strlen(address));

    // Sign message
    signature_len = ECDSA_size(key_pair_obj); // the signature size depends on the key
    signature     = (uint8_t *) OPENSSL_malloc(signature_len);
    digest        = SHA256((const unsigned char *)message, strlen(message), buffer_digest);
    ret_error     = ECDSA_sign(0, (const uint8_t *)digest, SHA256_DIGEST_LENGTH, signature, &signature_len, key_pair_obj);

    printf("\nMessage SHA256 (HEX): ");for (uint32_t i = 0; i < SHA256_DIGEST_LENGTH; i++) printf("%02x", digest   [i]); printf("\n");
    printf("Signature (HEX)     : "); for(uint32_t i = 0; i < signature_len       ; i++) printf("%02x", signature[i]); printf("\n");

    uint8_t pubkey_hash_verif[66] = {0};
    size_t decoded_len = 0;
    int len = base58_decode((char *)address, pubkey_hash_verif,&decoded_len);
    printShaHex("b58 decode ==> pubkeyhash : ",pubkey_hash_verif,25);
    printf("len = %zu\n",decoded_len);

    // Verify the signature
    verification = ECDSA_verify(0, digest, SHA256_DIGEST_LENGTH, signature, signature_len, key_pair_obj);
    if (verification == 1)
        printf("signature Verification    successful\n");
    else
        printf("signature Verification    NOT successful\n");
    EC_KEY_free(key_pair_obj);

    // Double check process for correctness
    imported_key_pair = EC_KEY_new_by_curve_name(NID_secp256k1);
    curve_group       = EC_GROUP_new_by_curve_name(NID_secp256k1);
    public_point      = EC_POINT_new(curve_group);
    public_point      = EC_POINT_hex2point(curve_group, pub_key_char, public_point, nullptr);
    ret_error         = EC_KEY_set_public_key(imported_key_pair, public_point);
    EC_GROUP_free(curve_group);
    EC_POINT_free(public_point);
    free(pub_key_char);

    bn        = BN_new();
    char_read = BN_hex2bn(&bn, priv_key_char);
    ret_error = EC_KEY_set_private_key(imported_key_pair, bn);
    BN_clear_free(bn);
    free(priv_key_char);

    verification = ECDSA_verify(0, digest, SHA256_DIGEST_LENGTH, signature, signature_len, imported_key_pair);
    if (verification == 1)
        printf("Re-Verification successful\n");
    else
        printf("Re-Verification NOT successful\n");

    printf("\nfree1\n");
    EC_KEY_free(imported_key_pair);
    printf("free2\n");
    OPENSSL_free(signature);
    printf("fin\n");

    return 0;
}
