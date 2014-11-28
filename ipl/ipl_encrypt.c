#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kirk_engine.h"
#include "ipl.h"

//IPL-ENCRYPTER SAMPLE

int EncryptIplBlock(IplEncBlock *dst, const void *src)
{
    int ret = kirk_CMD0(dst, (void*)src, 0xFD0);
    if(ret == KIRK_NOT_ENABLED){ printf("KIRK not enabled!\n"); return -1;}
    else if(ret == KIRK_INVALID_MODE){ printf("Mode in header not CMD1\n"); return -1;}
    else if(ret == KIRK_HEADER_HASH_INVALID){ printf("header hash check failed\n"); return -1;}
    else if(ret == KIRK_DATA_HASH_INVALID){ printf("data hash check failed\n"); return -1;}
    else if(ret == KIRK_DATA_SIZE_ZERO){ printf("data size = 0\n"); return -1;}
    return 0;
}

u8 ipl[MAX_IPLBLOCK_DATA_SIZE * MAX_NUM_IPLBLOCKS]; // buffer for IPL
struct {
    KIRK_CMD1_HEADER header;
    u8 data[3904];
} buf;
IplEncBlock encblk; // temp buffer for one 4KB encrypted IPL block

int main(int argc, char **argv)
{
    unsigned long int entry;
    int cur;
    u32 checksum = 0;
    IplBlock *bufBlock;

    if (argc != 2) {
        printf("usage: %s entry\n", argv[0]);
        return -1;
    }

    entry = strtoul(argv[1], NULL, 0);
    if (entry >= 0xB0000000) {
        printf("illegal entry\n");
        return -2;
    }

	//Open the file to decrypt, get it's size
    FILE *in = fopen("dec_ipl.bin", "rb");
    fseek(in, 0, SEEK_END);
    int size_dec = ftell(in);
    rewind(in);
    
    fread(ipl, size_dec, 1, in);
    fclose(in);
    
    //init KIRK crypto engine
    kirk_init(); 

    FILE *out = fopen("enc_ipl.bin", "wb");

    buf.header.mode = KIRK_MODE_CMD1;
    buf.header.ecdsa = 0;
    buf.header.data_offset = 0x200;

    bufBlock = (IplBlock *)(buf.data + buf.header.data_offset);
    bufBlock->loadaddr = entry;
    bufBlock->blocksize = 3392;
    bufBlock->entry = 0;
    bufBlock->checksum = 0;
    checksum = iplMemcpy(bufBlock->data, ipl, bufBlock->blocksize);

    buf.header.data_size = offsetof(IplBlock, data) + bufBlock->blocksize;

    if (EncryptIplBlock(&encblk, &buf) != 0)
    {
        printf("IPL block encryption failed!\n");
        fclose(out);
        return -1;
    }

    fwrite(&encblk, sizeof(encblk), 1, out);

    buf.header.data_offset = 0x10;
    
    bufBlock = (IplBlock *)(buf.data + buf.header.data_offset);
    bufBlock->blocksize = 3888;
    bufBlock->entry = 0;

    buf.header.data_size = offsetof(IplBlock, data) + bufBlock->blocksize;

    //encrypt all decrypted IPL blocks
    for (cur = bufBlock->blocksize; cur + bufBlock->blocksize < size_dec; cur += bufBlock->blocksize)
    {
        bufBlock->loadaddr = entry + cur;
        bufBlock->checksum = checksum;
        // load a single decrypted IPL block
        checksum = iplMemcpy(bufBlock->data, ipl + cur, bufBlock->blocksize);

        // encrypt the ipl block
        if (EncryptIplBlock(&encblk, &buf) != 0)
        {
            printf("IPL block encryption failed!\n");
            fclose(out);
            return -1;
        }

        fwrite(&encblk, sizeof(encblk), 1, out);
    }

    buf.header.ecdsa = 1;

    bufBlock->loadaddr = entry + cur;
    bufBlock->blocksize = size_dec - cur;
    bufBlock->entry = entry;
    bufBlock->checksum = checksum;
    memcpy(bufBlock->data, ipl + cur, bufBlock->blocksize);

    buf.header.data_size = offsetof(IplBlock, data) + bufBlock->blocksize;

    if (EncryptIplBlock(&encblk, &buf) != 0)
    {
        printf("IPL block encryption failed!\n");
        fclose(out);
        return -1;
    }

    fwrite(&encblk, sizeof(encblk), 1, out);

    fclose(out);
    printf("\nIPL encrypted successfully. \n");
    system("PAUSE");

	return 0;
}
