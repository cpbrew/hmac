#include <cstring>
#include "hmac_sha256.h"
#include "sha256.h"

const size_t B = 64,    // Byte length of hash function input block size
             L = 32;    // Byte length of hash function output block size
const char key_padding = 0x00;
const char ipad = 0x36;
const char opad = 0x5C;

void hmac_sha256(const char *message, size_t msg_len, const char *key, size_t key_len, uint8_t *digest)
{
    char padded_key[B];
    char *padded_message;

    // Pad the key to the required length
    memcpy(padded_key, key, key_len < B ? key_len : B);
    for (unsigned int i = key_len; i < B; i++)
    {
        padded_key[i] = key_padding;
    }

    // Xor the key with ipad and append the message contents
    padded_message = new char[B + (msg_len > L ? msg_len : L)];
    for (unsigned int i = 0; i < (B + msg_len); i++)
    {
        if (i < B)
        {
            padded_message[i] = padded_key[i] ^ ipad;
        }
        else
        {
            padded_message[i] = message[i - B];
        }
    }

    // Hash the (K+ xor ipad) padded message
    sha256(padded_message, B + msg_len, digest);

    // Xor the key with opad and append the hash from the previous step
    for (unsigned int i = 0; i < (B + L); i++)
    {
        if (i < B)
        {
            padded_message[i] = padded_key[i] ^ opad;
        }
        else
        {
            padded_message[i] = digest[i - B];
        }
    }

    // Apply the final hash
    sha256(padded_message, B + L, digest);
}
