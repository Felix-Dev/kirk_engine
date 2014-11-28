#include "kirk_engine.h"

#define MAX_IPLBLK_DATA_SIZE (3904)
#define MAX_IPL_SIZE         (0x80000)
#define MAX_NUM_IPLBLKS    (MAX_IPL_SIZE / sizeof(iplEncBlk))

typedef struct
{
    u32 addr;
    u32 size;
    u32 entry;
    u32 hash;
    u8 data[MAX_IPLBLK_DATA_SIZE];
} iplBlk;

typedef struct
{
    KIRK_CMD1_HEADER hdr;
    u8 data[3904];
    u8 unk[48];
} iplEncBlk;

static u32 iplMemcpy(void *dst, const void *src, size_t size)
{
	u32 *_dst = dst;
	const u32 *_src = src;
	u32 hash = 0;

	if (size & 3)
		return 0;

	while (size) {
		*_dst = *_src;
		hash += *_src;
		_dst++;
		_src++;
		size -= 4;
	}

	return hash;
}

