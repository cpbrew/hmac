#include <iostream>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include "hmac_sha256.h"

using namespace std;

void usage(const char *);

int main(int argc, char *argv[])
{
    char *message, *key, *my_hmac;
    streamsize message_s, key_s, hmac_s;
    fstream f;
    uint8_t digest[32];
    string mac, cryptopp_hmac;

    if (argc != 5)
    {
        usage(argv[0]);
    }

    // Read the message
    f.open(argv[3], ios::in | ios::ate);
    message_s = f.tellg();
    message = new char[message_s];
    f.seekg(0, ios::beg);
    f.read(message, message_s);
    f.close();

    // Read the key
    f.open(argv[2], ios::in | ios::binary | ios::ate);
    key_s = f.tellg();
    key = new char[key_s];
    f.seekg(0, ios::beg);
    f.read(key, key_s);
    f.close();

    if (strcmp("create", argv[1]) == 0)
    {
        // Calculate and store the hmac of the message
        hmac_sha256(message, message_s, key, key_s, digest);

        f.open(argv[4], ios::out);
        cout << "HMAC value:" << endl;
        for (int i = 0; i < 32; i++)
        {
            f << hex << uppercase << setw(2) << setfill('0') << ((int) (digest[i] & 0xFF));
            cout << hex << uppercase << setw(2) << setfill('0') << ((int) (digest[i] & 0xFF));
        }
        f.close();
        cout << endl;
    }
    else if (strcmp("verify", argv[1]) == 0)
    {
        // Calculate the hmac of the message using the CryptoPP library
        CryptoPP::HMAC<CryptoPP::SHA256> hmac((unsigned char *)key, key_s);
        CryptoPP::StringSource ss1(message, true,
            new CryptoPP::HashFilter(hmac,
                new CryptoPP::StringSink(mac)
            ) // HashFilter
        ); // StringSource
        CryptoPP::StringSource ss2(mac, true,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(cryptopp_hmac)
            ) // HexEncoder
        ); // StringSource

        // Read the hmac that we calculated earlier
        f.open(argv[4], ios::in | ios::ate);
        hmac_s = f.tellg();
        my_hmac = new char[hmac_s];
        f.seekg(0, ios::beg);
        f.read(my_hmac, hmac_s);
        f.close();

        // Compare the two
        cout << "My HMAC:" << endl << string(my_hmac) << endl;
        cout << "CryptoPP HMAC:" << endl << cryptopp_hmac << endl;

        if (cryptopp_hmac.compare(string(my_hmac)) == 0)
        {
            cout << "SUCCESS!" << endl;
        }
        else
        {
            cout << "Uh-oh..." << endl;
        }
    }
    else
    {
        usage(argv[0]);
    }

    return 0;
}

void usage(const char *name)
{
    cout << "Usage:" << endl;
    cout << name << " create keyFile messageFile outputFile" << endl;
    cout << name << " verify keyFile messageFile outputFile" << endl;

    exit(1);
}
