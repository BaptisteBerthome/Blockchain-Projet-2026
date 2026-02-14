// Vincent Dugat à partir d'un code posté
// par AB Music Box sur https://stackoverflow.com/q
// Retrieved 2025-12-22, License - CC BY-SA 4.0
// compil : gcc sha-ripem.c -o sha-ripem -lcrypto
// calcule une adresse bitcoin P2PKH en montrant
// les étapes intermédiaires
// Dépendances : libcrypto d'OPENSSL
//
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

#define nullptr NULL

typedef unsigned char byte;

void printShaHex(const char * msg,byte *digest,int len){
  // affiche un tableau binaire en hexadécimal
  printf("%s",msg);
  for (uint32_t i = 0; i < len; i++)
      printf("%02x", digest[i]);
  printf("\n");
}

void my_byte_copy(byte * receiver,byte * sender,uint8_t begin,uint8_t sender_length){
  //
  for (int i = 0 ; i < sender_length ; i++)
    receiver[i+begin] = sender[i];
}

void hex_string2int_array(byte * hex_string,uint8_t tab[33]){
  // convertit un tableaux de caractères hexadécimaux en son équivalent binaire
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

char* base58(byte *s, int s_size, char *out, int out_size) {
        static const char *tmpl = "123456789"
                "ABCDEFGHJKLMNPQRSTUVWXYZ"
                "abcdefghijkmnopqrstuvwxyz";

        int c, i, n;

        out[n = out_size] = 0;
        while (n--) {
                for (c = i = 0; i < s_size; i++) {
                        c = c * 256 + s[i];
                        s[i] = c / 58;
                        c %= 58;
                }
                out[n] = tmpl[c];
        }

        return out;
}

int main(){

  EC_KEY         *key_pair_obj = nullptr;
  int             ret_error;
  BIGNUM         *priv_key;
  EC_POINT       *pub_key;
  EC_GROUP       *secp256k1_group;
  char           *pub_key_char, *priv_key_char;

int c;


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

uint8_t tab[33] = {0};

unsigned long n = strlen(pub_key_char);
hex_string2int_array((byte *)pub_key_char,tab); // hex to binary
// calcul du sha256
unsigned char *d = SHA256((unsigned char *)tab, 33, 0);
unsigned char data[65], *p;
// recopie du sha dans un tableau
for (c = 0, p = data; c < 32; c++, p += 2){
        sprintf((char *)p, "%02x", d[c]);
     }
printf("data (sha) = %s", data);
putchar('\n');

// ripem160 (40 caractères HEX = 20 bytes)
unsigned char md[21];
unsigned char* pmd = RIPEMD160(d, strlen(d), md+1); // pmd pointe sur md

int i;
// impression en hex
printShaHex("ripem = ",pmd,20);

md[0] = 0; // ajout de 0x00 en tête = 21 bytes
printShaHex("md = ",md,21);

// checksum sha256 de md
unsigned char *cs = SHA256((unsigned char *)md, 21, 0);

printf("cs len = %lu\n",strlen((char *)cs));
printShaHex("First SHA = ",cs,32); // 32 bytes = 64 car HEX

// sha256 du précédent
unsigned char *cs2 = SHA256((unsigned char *)cs, 32, 0);
printShaHex("Second SHA256 = ",cs2,32);

printShaHex("checksum = ",cs2,4); // 8 premiers car HEX = 4 bytes

byte last[21+4] = {0};
my_byte_copy(last,md,0,21);
my_byte_copy(last,cs2,21,4);

printShaHex("keypub hash = ",last,21+4);

byte address[34]; // car HEX
base58(last, 21+4, (char *) address, 34);
printf("Legacy Address (P2PKH) = %s\n", address);
return 0;
}
