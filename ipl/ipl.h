#include "kirk_engine.h"

#define MAX_NUM_IPLBLOCKS    (0x80)
#define MAX_IPLBLOCK_DATA_SIZE (3904)
#define MAX_IPL_SIZE         (0x80000)

typedef struct
{
    u32 loadaddr;
    u32 blocksize;
    u32 entry;
    u32 checksum;
    u8 data[MAX_IPLBLOCK_DATA_SIZE];
} IplBlock;

typedef struct
{
    KIRK_CMD1_HEADER header;
    u8 data[sizeof(IplBlock)];
    u8 checksum[32];
} IplEncBlock;

static u32 iplMemcpy(void *dst, const void *src, int size)
{
	int i;
	u32 checksum = 0;

	for (i=0; i<size; i+=4)
	{
		*(u32*)(dst+i) = *(u32*)(src+i);
		checksum += *(u32*)(src+i);
	}

	return(checksum);
}

