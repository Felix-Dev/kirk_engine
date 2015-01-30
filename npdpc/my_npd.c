#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#include "kirk_engine.h"
#include "amctrl.h"

#include "tlzrc.c"

/*****************************************************************************/

u8 table[0x400000];
u8 data_buf[0x100000];
u8 decrypt_buf[0x200000];
u8 header[0x100];

/*****************************************************************************/

u8 header_key[16];
u8 *np_table;
int total_blocks;
int block_size;
u8 version_key[16];

/*****************************************************************************/

#define PBP_MAGIC 0x50425000

struct pbpHdr {
	u32 magic;
	u32 ver;
	u32 param_offset;
	u32 icon0_offset;
	u32 icon1_offset;
	u32 pic0_offset;
	u32 pic1_offset;
	u32 snd0_offset;
	u32 psp_offset;
	u32 psar_offset;
};

/*****************************************************************************/

int NpegOpen(FILE *fp, u32 offset, u8 *header, u8 *table, int *table_size)
{
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	u8 *np_header;
	int start, end, lba_size, offset_table;
	u32 *tp;
	int retv, i;

	np_header  = header;
	np_table   = table;

	if(fp == NULL || header == NULL || table == NULL || table_size == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (fseek(fp, offset, SEEK_SET))
		return -1;
	if (fread(np_header, 0x0100, 1, fp) <= 0)
		return -1;

	// check "NPUMDIMG"
	if(strncmp((char*)np_header, "NPUMDIMG", 8)){
		printf("DATA.PSAR isn't a NPUMDIMG!\n");
		return -7;
	}

	// bbmac_getkey
	sceDrmBBMacInit(&mkey, 3);
	sceDrmBBMacUpdate(&mkey, np_header, 0xc0);
	bbmac_getkey(&mkey, np_header+0xc0, version_key);

	// header MAC check
	sceDrmBBMacInit(&mkey, 3);
	sceDrmBBMacUpdate(&mkey, np_header, 0xc0);
	retv = sceDrmBBMacFinal2(&mkey, np_header+0xc0, version_key);
	if(retv){
		printf("NP header MAC check failed!\n");
		return -13;
	}

	write_file("version_key.bin", version_key, 16);

	// decrypt NP header
	memcpy(header_key, np_header+0xa0, 0x10);
	sceDrmBBCipherInit(&ckey, 1, 2, header_key, version_key, 0);
	sceDrmBBCipherUpdate(&ckey, np_header+0x40, 0x60);
	sceDrmBBCipherFinal(&ckey);

	start = *(u32*)(np_header+0x54); // LBA start
	end   = *(u32*)(np_header+0x64); // LBA end
	block_size = *(u32*)(np_header+0x0c); // block_size
	lba_size = (end-start+1); // LBA size of ISO
	total_blocks = (lba_size+block_size-1)/block_size; // total blocks;

	offset_table = *(u32*)(np_header+0x6c); // table offset
	fseek(fp, offset + offset_table, SEEK_SET);

	*table_size = total_blocks*32;
	retv = fread(np_table, *table_size, 1, fp);
	if(retv!=1)
		return -18;

	// table mac test
	int msize;
	u8 bbmac[16];

	sceDrmBBMacInit(&mkey, 3);
	for(i=0; i<*table_size; i+=0x8000){
		if(i+0x8000>*table_size)
			msize = *table_size-i;
		else
			msize = 0x8000;
		sceDrmBBMacUpdate(&mkey, np_table+i, msize);
	}
	sceDrmBBMacFinal(&mkey, bbmac, version_key);
	bbmac_build_final2(3, bbmac);

	tp = (u32*)np_table;
	for(i=0; i<total_blocks; i++){
		u32 a0, a1, a2, a3, v0, v1, t0, t1, t2;

		v1 = tp[0];
		v0 = tp[1];
		a0 = tp[2];
		t1 = tp[3];

		a1 = tp[4];
		a2 = tp[5];
		a3 = tp[6];
		t0 = tp[7];

		t2 = v1^v0;
		v0 = v0^a0;
		v1 = v1^t1;
		a0 = a0^t1;

		a1 = a1^a0;
		a2 = a2^v0;
		a3 = a3^v1;
		t0 = t0^t2;

		tp[4] = a1;
		tp[5] = a2;
		tp[6] = a3;
		tp[7] = t0;

		tp += 8;
	}

	return 0;
}

/*****************************************************************************/

int NpegReadBlock(FILE *fp, u32 offset, u8 *data_buf, u8 *out_buf, int block)
{
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	int retv;
	u32 *tp;

	tp = (u32*)(np_table+block*32);
	if(tp[7]!=0){
		if(block==(total_blocks-1))
			return 0x00008000;
		else
			return -1;
	}

	if (fseek(fp, offset + tp[4], SEEK_SET)) {
		if(block==(total_blocks-1))
			return 0x00008000;
		else
			return -1;
	}

	retv = fread(data_buf, tp[5], 1, fp);
	if(retv!=1){
		if(block==(total_blocks-1))
			return 0x00008000;
		else
			return -2;
	}

	if((tp[6]&1)==0){
		sceDrmBBMacInit(&mkey, 3);
		sceDrmBBMacUpdate(&mkey, data_buf, tp[5]);
		retv = sceDrmBBMacFinal2(&mkey, (u8*)tp, version_key);
		if(retv<0){
			if(block==(total_blocks-1))
				return 0x00008000;
			else
				return -5;
		}
	}

	if((tp[6]&4)==0){
		sceDrmBBCipherInit(&ckey, 1, 2, header_key, version_key, tp[4]>>4);
		sceDrmBBCipherUpdate(&ckey, data_buf, tp[5]);
		sceDrmBBCipherFinal(&ckey);
	}

	if(tp[5]<block_size*2048){
#if 0
		char name[32];
		//printf("block %4d: %08x\n", block, tp[5]);
		sprintf(name, "cdata/%4d.bin", block);
		write_file(name, data_buf, tp[5]);
		retv = 0x00008000;
#endif

		retv = lzrc_decompress(out_buf, 0x00100000, data_buf, tp[5]);
		if(retv!=block_size*2048){
			printf("LZR decompress error! retv=%d\n", retv);
		}
#if 0
// compress test
{
	u8 *dbuf, *ebuf;
	int esize, dsize;
	char name[32];

	ebuf = malloc(1024*1024);
	dbuf = malloc(1024*1024);
	memset(ebuf, 0, 1024*1024);
	memset(dbuf, 0, 1024*1024);

	esize = lzrc_compress(ebuf, 1024*1024, out_buf, retv);
	dsize = lzrc_decompress(dbuf, 1024*1024, ebuf, esize);
	if(dsize!=retv || memcmp(out_buf, dbuf, dsize)){
		printf("lzrc_compress failed on block %d!\n", block);
		sprintf(name, "lzrc_%4d.bin", block);
		write_file(name, data_buf, tp[5]);
	}

	free(ebuf);
	free(dbuf);
}
#endif

	}else{
		memcpy(out_buf, data_buf, tp[5]);
		retv = 0x00008000;
	}

	return retv;
}

/*****************************************************************************/

struct sdHdr {
	uint64_t magic;
	u32 unk1;
	u32 unk2;
	u32 hdrSize;
	u32 dataSize;
	u8 unk[56];
};

int main(int argc, char *argv[])
{
	struct pbpHdr hdr;
	int table_size, retv;
	int blocks, block_size;
	int start, end, iso_size;
	int i;
	char iso_name[64];
	u32 size;
	FILE *in, *out;

	printf("NP Decryptor for PC. Writen by tpu.\n");
	kirk_init();

	// Open and check PBP file
	in = fopen("NP.PBP", "rb");
	if(in == NULL) {
		perror("NP.PBP");
		return errno;
	}

	if (fread(&hdr, sizeof(hdr), 1, in) <= 0) {
		perror("NP.PBP");
		return errno;
	}

	if(hdr.magic != PBP_MAGIC) {
		printf("Not a valid PBP file!\n");
		return EILSEQ;
	}

	if (fseek(in, hdr.psp_offset + 1440 + offsetof(struct sdHdr, dataSize), SEEK_SET)) {
		perror("NP.PBP");
		return errno;
	}
	if (size > sizeof(data_buf)) {
		printf("NP.PBP: STARTDAT is too large.\n");
		return EFBIG;
	}
	if (fread(&size, sizeof(size), 1, in) <= 0) {
		perror("NP.PBP");
		return errno;
	}
	if (fseek(in, hdr.psp_offset + 1440 + 80, SEEK_SET)) {
		perror("NP.PBP");
		return errno;
	}
	if (fread(data_buf, size, 1, in) <= 0) {
		perror("NP.PBP");
		return errno;
	}
	out = fopen("STARTDAT.PNG", "wb");
	if (out == NULL) {
		perror("STARTDAT.PNG");
		return errno;
	}
	if (fwrite(data_buf, size, 1, out) != 1) {
		perror("STARTDAT.PNG");
		return errno;
	}
	if (fclose(out)) {
		perror("STARTDAT.PNG");
		return errno;
	}

	retv = NpegOpen(in, hdr.psar_offset, header, table, &table_size);
	if(retv < 0) {
		printf("NpegOpen Error! %08x\n", retv);
		return -1;
	}

	write_file("header.bin", header, 0x100);
	printf("table_size=%d\n", table_size);
	printf("Dumped header.\n\n");

	start = *(u32*)(header+0x54); // 0x54 LBA start
	end   = *(u32*)(header+0x64); // 0x64 LBA end
	iso_size = (end-start+1)*2048;

	block_size = *(u32*)(header+0x0c); // 0x0C block size?
	block_size *= 2048;

	printf("ISO name: %s.iso\n", header+0x70);
	printf("ISO size: %d MB\n", iso_size/0x100000);

	sprintf(iso_name, "%s.iso", header+0x70);
	out = fopen(iso_name, "wb");
	if(out == NULL){
		perror(iso_name);
		return errno;
	}

	blocks = table_size/32;

	for(i=0; i<blocks; i++){
		retv = NpegReadBlock(in, hdr.psar_offset, data_buf, decrypt_buf, i);
		if(retv<=0){
			printf("Error %08x reading block %d\n", retv, i);
			break;
		}
		fwrite(decrypt_buf, retv, 1, out);

		if((i&0x0f)==0){
			printf("Dumping... %3d%% %d/%d    \r", i*100/blocks, i, blocks);
		}
	}
	printf("\n\n");

	fclose(in);
	fclose(out);

	return 0;
}

