#include <iostream>
#include <cstring>
#include <cassert>
#include <iomanip>

using namespace std;

size_t doPreprocessing(const char *, uint32_t **);
uint64_t getPadding(uint64_t);

void byteArrayToIntArray(uint8_t *, uint32_t *, size_t);
void btoi(uint8_t *, uint32_t *);
void ltob(uint64_t, uint8_t *);
void usage(const char *);

// The initialization vector for SHA256
const uint32_t IV[8] = {0x6a09e667,
                        0xbb67ae85,
                        0x3c6ef372,
                        0xa54ff53a,
                        0x510e527f,
                        0x9b05688c,
                        0x1f83d9ab,
                        0x5be0cd19};

// The round constants for SHA256
const uint32_t K[64] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

int main(int argc, char *argv[])
{
    size_t blocks;
    uint32_t *data;

    if (argc != 3)
    {
        usage(argv[0]);
    }

    blocks = doPreprocessing(argv[1], &data);

    return 0;
}

// Convert the input message to an array of 32-bit blocks, including the padding and length
// and return the number of blocks
size_t doPreprocessing(const char *message, uint32_t **output)
{
    uint64_t paddingBytes;
    size_t msgBytes, totalBytes;
    uint8_t *buffer;

    msgBytes = strlen(message);
    paddingBytes = getPadding(msgBytes);
    totalBytes = msgBytes + paddingBytes + 8;

    buffer = new uint8_t[totalBytes];
    memcpy(buffer, message, msgBytes);

    // Copy in the padding bits
    buffer[msgBytes] = (uint8_t) 0x80;
    for (unsigned int i = 1; i < paddingBytes; i++)
    {
        buffer[(msgBytes + 1) + i] = (uint8_t) 0x00;
    }

    // Copy in the message length (in bits)
    ltob(msgBytes * 8, &(buffer[msgBytes + paddingBytes]));

    // Convert the byte buffer to the output format
    *output = new uint32_t[totalBytes / 4];
    byteArrayToIntArray(buffer, *output, totalBytes);

    delete buffer;
    return totalBytes / 4;
}

// Calculate how many padding bytes are needed for a message of a given length
uint64_t getPadding(uint64_t len)
{
    uint64_t padding;

    len += 8;                       // we're going to need an extra 64 bits (8 bytes) to store the length
    padding = 64 - (len % 64);      // Block size is 512 bits (64 bytes)
    if (padding == 0) padding = 64; // Always pad the message, even if it starts out the correct length
    return padding;
}

// Convert an array of bytes to an array of 32-bit integers
void byteArrayToIntArray(uint8_t *byteArray, uint32_t *intArray, size_t bytes)
{
    for (unsigned int i = 0; i < bytes; i += 4)
    {
        btoi(&(byteArray[i]), &(intArray[i / 4]));
    }
}

// Convert an array of bytes to a 32-bit integer
void btoi(uint8_t *b, uint32_t *i)
{
    *i = 0;
    for (int j = 0; j < 4; j++)
    {
        *i <<= 8;
        *i |= b[j];
    }
}

// Convert a 64-bit integer to an array of bytes
void ltob(uint64_t l, uint8_t *b)
{
    for (int i = 7; i >= 0; i--)
    {
        b[i] = (uint8_t) (l & 0xFF);
        l >>= 8;
    }
}

// Print a help message and exit
void usage(const char *name)
{
    cout << "Usage:" << endl;
    cout << name << " password keyFile" << endl;

    exit(1);
}