#include <iostream>
#include <iomanip>
#include <fstream>
#include "sha256.h"

using namespace std;

void usage(const char *);

int main(int argc, char *argv[])
{
    uint32_t *digest;
    fstream f;

    if (argc != 3)
    {
        usage(argv[0]);
    }

    digest = sha256(argv[1]);

    f.open(argv[2], ios::out);
    for (int i = 0; i < 8; i++)
    {
        f << hex << uppercase << setw(8) << setfill('0') << digest[i];
    }
    f << endl;
    f.close();
}

// Print a help message and exit
void usage(const char *name)
{
    cout << "Usage:" << endl;
    cout << name << " password keyFile" << endl;

    exit(1);
}
