#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kirk_engine.h"
#include "ipl.h"

//IPL-DECRYPTER SAMPLE

static void printHEX(int hex)
{
	if(hex < 0x10) printf("0%X", hex);
	else printf("%X", hex);
}

void PrintKIRK1Header(u8* buf)
{
    KIRK_CMD1_HEADER* header = (KIRK_CMD1_HEADER*)buf;
    printf("AES encrypted key:\n");
    int i;
    for(i = 0; i < 16; i++)
    {
		printHEX(header->AES_key[i]);
    }
    printf("\nCMAC encrypted key:\n");
    for(i = 0; i < 16; i++)
    {
		printHEX(header->CMAC_key[i]);
    }
    printf("\nCMAC header hash:\n");
    for(i = 0; i < 16; i++)
    {
		printHEX(header->CMAC_header_hash[i]);
    }
    printf("\nCMAC data hash:\n");
    for(i = 0; i < 16; i++)
    {
		printHEX(header->CMAC_data_hash[i]);
    }
    printf("\nmode: %d, data_size 0x%X, data_offset 0x%X\n", header->mode, header->data_size, header->data_offset);
}

int DecryptiplBlk(iplBlk *dst, const iplEncBlk *src)
{
    //PrintKIRK1Header((void*)src);
    int ret = kirk_CMD1(dst, (void*)src, 0x1000);
    if(ret == KIRK_NOT_ENABLED){ printf("KIRK not enabled!\n"); return -1;}
    else if(ret == KIRK_INVALID_MODE){ printf("Mode in header not CMD1\n"); return -1;}
    else if(ret == KIRK_HEADER_HASH_INVALID){ printf("header hash check failed\n"); return -1;}
    else if(ret == KIRK_DATA_HASH_INVALID){ printf("data hash check failed\n"); return -1;}
    else if(ret == KIRK_DATA_SIZE_ZERO){ printf("data size = 0\n"); return -1;}
    return 0;
}

u8 ipl[MAX_IPL_SIZE]; // buffer for IPL
iplBlk decblk;      // decrypted IPL block
iplEncBlk encblk;   // temp buffer for one 4KB encrypted IPL block

int main()
{
    int i;
    int size = 0;
    int error = 0;
    u32 hash = 0;
	//Open the file to decrypt, get it's size
    FILE *in = fopen("enc_ipl.bin", "rb");
    fseek(in, 0, SEEK_END);
    int size_enc = ftell(in);
    rewind(in);
    
    fread(ipl, MAX_IPL_SIZE, 1, in);
    
    //init KIRK crypto engine
    kirk_init(); 
    
    //decrypt all encrypted IPL blocks
    for (i=0; i<size_enc/sizeof(encblk); i++)
    {
        // load a single encrypted IPL block (4KB block)
        memcpy(&encblk, ipl + i*sizeof(encblk), sizeof(encblk));

        // decrypt the ipl block
        if (DecryptiplBlk(&decblk, &encblk) != 0)
        {
            printf("IPL block decryption failed! iplblk - %d \n", i);
            error = 1;
            break;
        }

        // note first block has zero as its hash
        if (decblk.hash != hash)
        {
            printf("ipl block hash failed: iplblk - %d, hash - 0x%08X \n", i, decblk.hash);
            error = 1;
            break;
        }

        // copy the 'data' section of the decrypted IPL block
        if (decblk.addr)
        {
            hash = iplMemcpy(ipl+size, decblk.data, decblk.size);
            size += decblk.size;
        }

        // reached the last IPL block, save it
        if (decblk.entry /*&& !error*/)
        {
            FILE *out = fopen("dec_ipl.bin", "wb");
            fwrite(ipl, size, 1, out);
            fclose(out);
            printf("\nIPL decrypted successfully. \n");
            system("PAUSE");
	        return 0;
        }
    }

    printf("Decryption failed. \n");

	return 0;
}
