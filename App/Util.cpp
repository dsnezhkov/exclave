#include "Util.hpp"

HINSTANCE importEBridge(LPCWSTR bridgeDll) {

    HINSTANCE hinstLib;

    // Get a handle to the DLL module.
    hinstLib = LoadLibrary(bridgeDll);

    if (hinstLib != NULL)
        return hinstLib;
    else
        return NULL;

}

void WriteBufFile(const char* fileName, const char* buf, size_t sz) {

    std::ofstream outfile(fileName, std::ofstream::binary);

    outfile.write(buf, sz);
    outfile.close();
}

void DumpHex(void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        }
        else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            }
            else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}
