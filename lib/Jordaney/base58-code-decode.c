#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test.h"

char* base58_encode(byte *s, int s_size, char *out, int out_size) {
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

static const char *BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int base58_decode(const char *base58, uint8_t *decoded, size_t *decoded_len) {
    size_t input_len = strlen(base58); // Length of the input Base58 string
    //printf("===> input |%s| l : %lu\n",base58,input_len);
    size_t output_len = 0;            // Length of the decoded output
    memset(decoded, 0, *decoded_len); // Initialize the output buffer with zeros

    for (size_t i = 0; i < input_len; i++) {
        const char *p = strchr(BASE58_ALPHABET, base58[i]); // Find character in Base58 alphabet
        if (!p) return 0; // Return 0 if the character is invalid
        int carry = p - BASE58_ALPHABET; // Get the numeric value of the character

        for (size_t j = 0; j < output_len; j++) {
            carry += decoded[j] * 58;  // Multiply by 58 and add the carry
            decoded[j] = carry & 0xFF; // Store the least significant byte
            carry >>= 8;               // Carry the overflow to the next byte
        }

        while (carry) { // Append carry bytes if necessary
            decoded[output_len++] = carry & 0xFF;
            carry >>= 8;
        }
    }
    output_len++;
    for (size_t i = 0; i < output_len / 2; i++) { // Reverse byte order
        uint8_t temp = decoded[i];
        decoded[i] = decoded[output_len - 1 - i];
        decoded[output_len - 1 - i] = temp;
    }

    *decoded_len = output_len; // Set the output length
    return 1;                  // Return success
}
