#ifndef HMAC_SHA256_H_INCLUDED
#define HMAC_SHA256_H_INCLUDED

#include <cstdint>
#include <cstdlib>

void hmac_sha256(const char *, size_t, const char *, size_t, uint8_t *);

#endif // HMAC_SHA256_H_INCLUDED
