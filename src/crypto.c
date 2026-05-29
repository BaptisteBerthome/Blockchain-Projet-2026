#include "../include/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if USE_REAL_ECDSA
// =====================================================================
//  MODE REEL : OpenSSL (secp256k1, P2PKH, ECDSA)
// =====================================================================

// Decoupe une chaine hexa en octets. Retourne le nombre d'octets ecrits.
static int hex_to_bytes(const char *hex, unsigned char *out, int out_max) {
    int n = (int)strlen(hex) / 2;
    if (n > out_max) n = out_max;
    for (int i = 0; i < n; i++) {
        char b[3] = { hex[2 * i], hex[2 * i + 1], '\0' };
        out[i] = (unsigned char)strtol(b, NULL, 16);
    }
    return n;
}

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>

// base58 
static char *base58(unsigned char *s, int s_size, char *out, int out_size) {
    static const char *tmpl =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
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

// hash160 brut (20 octets) a partir d'une cle publique hexa
static void hash160_raw(const char *pubkey_hex, unsigned char out20[20]) {
    unsigned char pub_bytes[65];
    int pl = hex_to_bytes(pubkey_hex, pub_bytes, sizeof(pub_bytes));
    unsigned char sha[32];
    SHA256(pub_bytes, pl, sha);
    RIPEMD160(sha, 32, out20);
}

void crypto_hash160(const char *pubkey_hex, char *out_hex) {
    unsigned char md[20];
    hash160_raw(pubkey_hex, md);
    for (int i = 0; i < 20; i++) {
        sprintf(&out_hex[i * 2], "%02x", md[i]);
    }
    out_hex[40] = '\0';
}

void crypto_generate_keypair(char *priv_hex, char *pub_hex, char *address) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(key);

    // cle privee (hexa)
    const BIGNUM *priv = EC_KEY_get0_private_key(key);
    char *ph = BN_bn2hex(priv);
    snprintf(priv_hex, PRIVKEY_HEX_LEN, "%s", ph);

    // cle publique compressee (hexa)
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *pub = EC_KEY_get0_public_key(key);
    char *pbh = EC_POINT_point2hex(group, pub, POINT_CONVERSION_COMPRESSED, NULL);
    snprintf(pub_hex, PUBKEY_HEX_LEN, "%s", pbh);

    // adresse P2PKH = base58check( version || hash160(pubkey) )
    unsigned char md[21];
    md[0] = ADDRESS_VERSION_BYTE;
    hash160_raw(pub_hex, md + 1);

    unsigned char checksum[32];
    SHA256(md, 21, checksum);
    SHA256(checksum, 32, checksum); // double SHA256

    unsigned char payload[25];
    memcpy(payload, md, 21);
    memcpy(payload + 21, checksum, 4);

    base58(payload, 25, address, 34);
    address[34] = '\0';

    OPENSSL_free(ph);
    OPENSSL_free(pbh);
    EC_KEY_free(key);
}

bool crypto_sign(const char *priv_hex, const char *message, char *sig_hex) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    BIGNUM *bn = NULL;
    BN_hex2bn(&bn, priv_hex);
    EC_KEY_set_private_key(key, bn);

    unsigned char digest[32];
    SHA256((const unsigned char *)message, strlen(message), digest);

    ECDSA_SIG *sig = ECDSA_do_sign(digest, 32, key);
    bool ok = false;
    if (sig != NULL) {
        unsigned char der[128];
        unsigned char *p = der;
        int len = i2d_ECDSA_SIG(sig, &p);
        if (len > 0 && len * 2 < SIG_HEX_LEN) {
            for (int i = 0; i < len; i++) {
                sprintf(&sig_hex[i * 2], "%02x", der[i]);
            }
            sig_hex[len * 2] = '\0';
            ok = true;
        }
        ECDSA_SIG_free(sig);
    }

    BN_free(bn);
    EC_KEY_free(key);
    return ok;
}

bool crypto_verify(const char *pub_hex, const char *message, const char *sig_hex) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *point = EC_POINT_new(group);

    bool ok = false;
    if (EC_POINT_hex2point(group, pub_hex, point, NULL) != NULL &&
        EC_KEY_set_public_key(key, point) == 1) {

        unsigned char der[128];
        int dlen = hex_to_bytes(sig_hex, der, sizeof(der));
        const unsigned char *p = der;
        ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, dlen);
        if (sig != NULL) {
            unsigned char digest[32];
            SHA256((const unsigned char *)message, strlen(message), digest);
            ok = (ECDSA_do_verify(digest, 32, sig, key) == 1);
            ECDSA_SIG_free(sig);
        }
    }

    EC_POINT_free(point);
    EC_KEY_free(key);
    return ok;
}

#else
// =====================================================================
//  MODE SIMPLIFIE (fallback du prof, sans OpenSSL)
// ---------------------------------------------------------------------
//  Une "paire de cles" partage un identifiant commun :
//      priv = "PRIVKEY-<id>"   pub = "PUBKEY-<id>"
//  Une signature embarque cet identifiant : "SIG-<id>".
//  VER est alors vrai si l'id de la signature == l'id de la cle publique
//  (c'est exactement le "<tx sign X> + <pubKey Y> -> true si X==Y").
// =====================================================================
#include "../include/sha256_utils.h" // SHA256 du projet (mode simplifie)

// renvoie un pointeur sur l'identifiant apres le '-' (ou la chaine entiere)
static const char *id_part(const char *s) {
    const char *dash = strchr(s, '-');
    return dash ? dash + 1 : s;
}

void crypto_hash160(const char *pubkey_hex, char *out_hex) {
    // hash simplifie : on reutilise le SHA256 du projet, tronque a 40 car
    char full[HASHLENGTH];
    sha256ofString((BYTE *)pubkey_hex, full);
    memcpy(out_hex, full, 40);
    out_hex[40] = '\0';
}

void crypto_generate_keypair(char *priv_hex, char *pub_hex, char *address) {
    static unsigned int counter = 0;
    unsigned int id = (((unsigned int)rand() << 8) ^ counter) & 0xFFFFFF;
    counter++;
    snprintf(priv_hex, PRIVKEY_HEX_LEN, "PRIVKEY-%06x", id);
    snprintf(pub_hex, PUBKEY_HEX_LEN, "PUBKEY-%06x", id);
    snprintf(address, ADDRESS_STR_LEN, "addr-%06x", id);
}

bool crypto_sign(const char *priv_hex, const char *message, char *sig_hex) {
    (void)message;
    snprintf(sig_hex, SIG_HEX_LEN, "SIG-%s", id_part(priv_hex));
    return true;
}

bool crypto_verify(const char *pub_hex, const char *message, const char *sig_hex) {
    (void)message;
    return strcmp(id_part(sig_hex), id_part(pub_hex)) == 0;
}

#endif // USE_REAL_ECDSA
