#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#include "kirk_engine.h"
#include "amctrl.h"

#include "pgd.c"
#include "tlzrc.c"

#define PBP_MAGIC 0x50425000
#define STARTDAT_MAGIC 0x5441445452415453

typedef struct pbpHdr {
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
} pbpHdr;

typedef struct {
	u8 unk0[12];
	uint64_t magic;
	u32 unk1;
	u32 unk2;
	u32 hdrSize;
	u32 dataSize;
	u8 unk3[56];
} sdHdr;

typedef struct {
	u8 hdrKey[16];
	u8 verKey[16];
	u8 hdr[208];
	u8 *tbl;
	size_t tblSize;
	int blkNum;
	size_t blkSize;
	u32 lbaStart;
	u32 lbaEnd;
	size_t lbaSize;
} np_t;

static int NpegOpen(np_t *np, FILE *fp, u32 offset)
{
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	int offset_table;
	u32 *tp;
	int retv, i;

	if(fp == NULL || np == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (fseek(fp, offset, SEEK_SET))
		return -1;
	if (fread(np->hdr, sizeof(np->hdr), 1, fp) <= 0)
		return -1;

	// check "NPUMDIMG"
	if(strncmp((char*)np->hdr, "NPUMDIMG", 8)){
		printf("DATA.PSAR isn't a NPUMDIMG!\n");
		return -7;
	}

	// bbmac_getkey
	sceDrmBBMacInit(&mkey, 3);
	sceDrmBBMacUpdate(&mkey, np->hdr, 0xc0);
	bbmac_getkey(&mkey, np->hdr + 0xc0, np->verKey);

	// np->hdr MAC check
	sceDrmBBMacInit(&mkey, 3);
	sceDrmBBMacUpdate(&mkey, np->hdr, 0xc0);
	retv = sceDrmBBMacFinal2(&mkey, np->hdr+0xc0, np->verKey);
	if(retv){
		printf("NP np->hdr MAC check failed!\n");
		return -13;
	}

	// decrypt NP np->hdr
	memcpy(np->hdrKey, np->hdr+0xa0, 0x10);
	sceDrmBBCipherInit(&ckey, 1, 2, np->hdrKey, np->verKey, 0);
	sceDrmBBCipherUpdate(&ckey, np->hdr+0x40, 0x60);
	sceDrmBBCipherFinal(&ckey);

	printf("NPUMDIMG Version Key: 0x");
	for (i = 0; i < 16; i++)
		printf("%02X", np->verKey[i]);
	printf("\nNPUMDIMG np->hdr Key:  0x");
	for (i = 0; i < 16; i++)
		printf("%02X", np->hdrKey[i]);
	putchar('\n');

	np->lbaStart = *(u32 *)(np->hdr + 0x54);
	np->lbaEnd = *(u32 *)(np->hdr + 0x64);
	np->lbaSize = np->lbaEnd - np->lbaStart + 1;

	np->blkNum = np->tblSize / 32;
	np->blkSize = *(u32 *)(np->hdr + 0x0c);
	np->blkNum = (np->lbaSize + np->blkSize - 1) / np->blkSize;

	offset_table = *(u32*)(np->hdr+0x6c); // table offset
	fseek(fp, offset + offset_table, SEEK_SET);

	np->tblSize = np->blkNum*32;
	np->tbl = malloc(np->tblSize);
	if (np->tbl == NULL)
		return -1;
	retv = fread(np->tbl, np->tblSize, 1, fp);
	if(retv!=1)
		return -18;

	// table mac test
	int msize;
	u8 bbmac[16];

	sceDrmBBMacInit(&mkey, 3);
	for(i=0; i<np->tblSize; i+=0x8000){
		if(i+0x8000>np->tblSize)
			msize = np->tblSize-i;
		else
			msize = 0x8000;
		sceDrmBBMacUpdate(&mkey, np->tbl+i, msize);
	}
	sceDrmBBMacFinal(&mkey, bbmac, np->verKey);
	bbmac_build_final2(3, bbmac);

	tp = (u32*)np->tbl;
	for(i=0; i<np->blkNum; i++){
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

static int NpegReadBlock(np_t *np, FILE *fp, u32 offset, u8 *data_buf, u8 *out_buf, int block)
{
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	int retv;
	u32 *tp;

	tp = (u32*)(np->tbl+block*32);
	if(tp[7]!=0){
		if(block==(np->blkNum-1))
			return 0x00008000;
		else
			return -1;
	}

	if (fseek(fp, offset + tp[4], SEEK_SET)) {
		if(block==(np->blkNum-1))
			return 0x00008000;
		else
			return -1;
	}

	retv = fread(data_buf, tp[5], 1, fp);
	if(retv!=1){
		if(block==(np->blkNum-1))
			return 0x00008000;
		else
			return -2;
	}

	if((tp[6]&1)==0){
		sceDrmBBMacInit(&mkey, 3);
		sceDrmBBMacUpdate(&mkey, data_buf, tp[5]);
		retv = sceDrmBBMacFinal2(&mkey, (u8*)tp, np->verKey);
		if(retv<0){
			if(block==(np->blkNum-1))
				return 0x00008000;
			else
				return -5;
		}
	}

	if((tp[6]&4)==0){
		sceDrmBBCipherInit(&ckey, 1, 2, np->hdrKey, np->verKey, tp[4]>>4);
		sceDrmBBCipherUpdate(&ckey, data_buf, tp[5]);
		sceDrmBBCipherFinal(&ckey);
	}

	if(tp[5]<np->blkSize*2048){
		retv = lzrc_decompress(out_buf, 0x00100000, data_buf, tp[5]);
		if(retv!=np->blkSize*2048){
			printf("LZR decompress error! retv=%d\n", retv);
		}

	}else{
		memcpy(out_buf, data_buf, tp[5]);
		retv = 0x00008000;
	}

	return retv;
}

static void NpegClose(const np_t *np)
{
	free(np->tbl);
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	pbpHdr hdr;
	np_t np;
	int retv, i;
	char iso_name[64];
	uint64_t magic;
	u32 offset, size;
	void *data, *dec;
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

	retv = NpegOpen(&np, in, hdr.psar_offset);
	if(retv < 0) {
		printf("NpegOpen Error! %08x\n", retv);
		return -1;
	}

	if (fseek(in, hdr.psp_offset + 1428 + offsetof(sdHdr, magic), SEEK_SET)) {
		perror("NP.PBP");
		return errno;
	}
	if (fread(&magic, sizeof(magic), 1, in) <= 0) {
		perror("NP.PBP");
		return errno;
	}
	if (magic == STARTDAT_MAGIC) {
		if (fseek(in, hdr.psp_offset + 1428 + offsetof(sdHdr, dataSize), SEEK_SET)) {
			perror("NP.PBP");
			return errno;
		}
		if (fread(&size, sizeof(size), 1, in) <= 0) {
			perror("NP.PBP");
			return errno;
		}
		data = malloc(size);
		if (data == NULL) {
			perror(NULL);
			return errno;
		}
		if (fseek(in, hdr.psp_offset + 1428 + sizeof(sdHdr), SEEK_SET)) {
			perror("NP.PBP");
			return errno;
		}
		if (fread(data, size, 1, in) <= 0) {
			perror("NP.PBP");
			return errno;
		}
		out = fopen("STARTDAT.PNG", "wb");
		if (out == NULL) {
			perror("STARTDAT.PNG");
			return errno;
		}
		if (fwrite(data, size, 1, out) != 1) {
			perror("STARTDAT.PNG");
			return errno;
		}
		if (fclose(out)) {
			perror("STARTDAT.PNG");
			return errno;
		}
		free(data);
	}

	if (fseek(in, hdr.psp_offset + 48, SEEK_SET)) {
		perror("NP.PBP");
		return errno;
	}
	if (fread(&offset, sizeof(offset), 1, in) <= 0) {
		perror("NP.PBP");
		return errno;
	}
	if (offset) {
		if (fread(&size, sizeof(size), 1, in) <= 0) {
			perror("NP.PBP");
			return errno;
		}
		data = malloc(size);
		if (data == NULL) {
			perror(NULL);
			return errno;
		}
		if (fseek(in, offset, SEEK_SET)) {
			perror("NP.PBP");
			return errno;
		}
		if (fread(data, size, 1, in) <= 0) {
			perror("NP.PBP");
			return errno;
		}
		size = pgd_decrypt(data, size, 2, np.verKey);
		if (pgd_decrypt < 0) {
			printf("NP.PBP: PGD decryption failed.\n");
			return -1;
		}
		out = fopen("OPNSSMP.BIN", "wb");
		if (out == NULL) {
			perror("OPNSSMP.BIN");
			return errno;
		}
		if (fwrite(data, size, 1, out) <= 0) {
			perror("OPNSSMP.BIN");
			return errno;
		}
		if (fclose(out)) {
			perror("OPNSSMP.BIN");
			return errno;
		}
		free(data);
	}

	data = malloc(np.blkSize * 2048);
	dec = malloc(np.blkSize * 2048);
	if (dec == NULL) {
		perror(NULL);
		return errno;
	}

	printf("ISO name: %s.iso\n", np.hdr+0x70);
	printf("ISO size: %zd MB\n", np.lbaSize * 2048 / 0x100000);

	sprintf(iso_name, "%s.iso", np.hdr+0x70);
	out = fopen(iso_name, "wb");
	if(out == NULL){
		perror(iso_name);
		return errno;
	}

	for(i = 0; i < np.blkNum; i++){
		retv = NpegReadBlock(&np, in, hdr.psar_offset, data, dec, i);
		if(retv<=0){
			printf("Error %08x reading block %d\n", retv, i);
			break;
		}
		fwrite(dec, retv, 1, out);

		if((i&0x0f)==0){
			printf("Dumping... %3d%% %d/%d    \r", i * 100 / np.blkNum, i, np.blkNum);
		}
	}
	printf("\n\n");

	fclose(in);
	fclose(out);
	free(dec);
	NpegClose(&np);

	return 0;
}

