#include <iostream>
#include <cstring>
#include <fstream>
#include <iomanip>
#include "sha256.h"

using namespace std;

void usage(const char *);

int main(int argc, char *argv[])
{
    uint8_t digest[32];
    fstream f;

    if (argc != 3)
    {
        usage(argv[0]);
    }

    sha256(argv[1], strlen(argv[1]), digest);

    cout << "Hash value:" << endl;
    for (int i = 0; i < 32; i++)
    {
        cout << hex << uppercase << setw(2) << setfill('0') << ((int) (digest[i] & 0xFF));
    }
    cout << endl;

    f.open(argv[2], ios::out | ios::binary);
    f.write((const char *) digest, 32);
    f.close();
}

// Print a help message and exit
void usage(const char *name)
{
    cout << "Usage:" << endl;
    cout << name << " password keyFile" << endl;

    exit(1);
}
