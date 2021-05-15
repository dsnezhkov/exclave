#include <fstream>

void WriteBufFile(const char* fileName, char* buf, size_t sz) {

    std::ofstream outfile(fileName, std::ofstream::binary);

    outfile.write(buf, sz);
    outfile.close();
}

void buf2hex(uint8_t* buf, unsigned int sz) {

    unsigned int i;
    for (i = 0; i < sz; i++)
    {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

void DumpHex(const void* data, size_t size) {
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

int readBin(const char* bin_file_name, unsigned char** buffer)
{

    size_t readed = 0;
    FILE* input = fopen(bin_file_name, "rb");
    int file_size = 0;

    //get Filesize 
    fseek(input, 0, SEEK_END);
    file_size = ftell(input);
    rewind(input);

    //Allocate memory for buffer
    *buffer = (unsigned char*)malloc(file_size);

    //Fill Buffer
    readed = fread(*buffer, file_size, 1, input);

    return 0;
}