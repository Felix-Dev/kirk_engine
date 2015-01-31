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
	uint32_t magic;
	uint32_t ver;
	uint32_t param_offset;
	uint32_t icon0_offset;
	uint32_t icon1_offset;
	uint32_t pic0_offset;
	uint32_t pic1_offset;
	uint32_t snd0_offset;
	uint32_t psp_offset;
	uint32_t psar_offset;
} pbpHdr;

typedef struct {
	uint8_t unk0[12];
	uint64_t magic;
	uint32_t unk1;
	uint32_t unk2;
	uint32_t hdrSize;
	uint32_t dataSize;
	uint8_t unk3[56];
} sdHdr;

typedef struct {
	uint8_t hdrKey[16];
	uint8_t verKey[16];
	uint8_t *tbl;
	size_t tblSize;
	int blkNum;
	size_t blkSize;
	uint32_t lbaStart;
	uint32_t lbaEnd;
	size_t lbaSize;
} np_t;

static int npOpen(np_t *np, FILE *fp, uint32_t offset)
{
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	int ret, i;
	char hdr[208];
	uint32_t *tp;
	uint8_t bbmac[16];

	if (np == NULL || fp == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (fseek(fp, offset, SEEK_SET))
		return -1;
	if (fread(hdr, sizeof(hdr), 1, fp) <= 0)
		return -1;

	if (strncmp(hdr, "NPUMDIMG", 8)){
		printf("DATA.PSAR isn't a NPUMDIMG!\n");
		errno = EILSEQ;
		return -1;
	}

	sceDrmBBMacInit(&mkey, 3);
	sceDrmBBMacUpdate(&mkey, hdr, 0xc0);
	bbmac_getkey(&mkey, hdr + 0xc0, np->verKey);

	sceDrmBBMacInit(&mkey, 3);
	sceDrmBBMacUpdate(&mkey, hdr, 0xc0);
	ret = sceDrmBBMacFinal2(&mkey, hdr + 0xc0, np->verKey);
	if (ret) {
		printf("NP Header MAC check failed!\n");
		return ret;
	}

	memcpy(np->hdrKey, hdr + 0xa0, 0x10);
	sceDrmBBCipherInit(&ckey, 1, 2, np->hdrKey, np->verKey, 0);
	sceDrmBBCipherUpdate(&ckey, hdr + 0x40, 0x60);
	sceDrmBBCipherFinal(&ckey);

	printf("NPUMDIMG Version Key: 0x");
	for (i = 0; i < 16; i++)
		printf("%02X", np->verKey[i]);
	printf("\nNPUMDIMG Header Key:  0x");
	for (i = 0; i < 16; i++)
		printf("%02X", np->hdrKey[i]);
	putchar('\n');

	np->lbaStart = *(uint32_t *)(hdr + 0x54);
	np->lbaEnd = *(uint32_t *)(hdr + 0x64);
	np->lbaSize = np->lbaEnd - np->lbaStart + 1;

	np->blkSize = *(uint32_t *)(hdr + 0x0c);
	np->blkNum = (np->lbaSize - 1) / np->blkSize;

	np->tblSize = np->blkNum * 32;
	np->tbl = malloc(np->tblSize);
	if (np->tbl == NULL)
		return -1;
	if (fseek(fp, offset + *(uint32_t *)(hdr + 0x6C), SEEK_SET))
		return -1;
	if (fread(np->tbl, np->tblSize, 1, fp) <= 0)
		return -1;

	// table mac test
	sceDrmBBMacInit(&mkey, 3);
	for (i = 0; i < np->tblSize; i+=0x8000)
		sceDrmBBMacUpdate(&mkey, np->tbl+i, i + 0x8000 > np->tblSize ? np->tblSize - i : 0x8000);
	sceDrmBBMacFinal(&mkey, bbmac, np->verKey);
	bbmac_build_final2(3, bbmac);

	tp = (uint32_t *)np->tbl;
	for (i = 0; i < np->blkNum; i++) {
		tp[4] ^= tp[2] ^ tp[3];
		tp[5] ^= tp[1] ^ tp[2];
		tp[6] ^= tp[0] ^ tp[3];
		tp[7] ^= tp[0] ^ tp[1];

		tp += 8;
	}

	return 0;
}

static int npRead(np_t *np, FILE *fp, uint32_t offset, uint8_t *data_buf, uint8_t *out_buf, int block)
{
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	int ret;
	uint32_t *tp;

	tp = (uint32_t *)(np->tbl + block*32);
	if (tp[7]) {
		errno = EILSEQ;
		return -1;
	}

	if (fseek(fp, offset + tp[4], SEEK_SET))
		return -1;

	if (fread(data_buf, tp[5], 1, fp))
		return -1;

	if (!(tp[6] & 1)) {
		sceDrmBBMacInit(&mkey, 3);
		sceDrmBBMacUpdate(&mkey, data_buf, tp[5]);
		ret = sceDrmBBMacFinal2(&mkey, (uint8_t*)tp, np->verKey);
		if (ret)
			return ret;
	}

	if (!(tp[6] & 4)) {
		sceDrmBBCipherInit(&ckey, 1, 2, np->hdrKey, np->verKey, tp[4] >> 4);
		sceDrmBBCipherUpdate(&ckey, data_buf, tp[5]);
		sceDrmBBCipherFinal(&ckey);
	}

	if (tp[5] < np->blkSize * 2048) {
		ret = lzrc_decompress(out_buf, 0x00100000, data_buf, tp[5]);
		if (ret != np->blkSize * 2048)
			printf("LZR decompress error! retv=%d\n", ret);
	} else {
		memcpy(out_buf, data_buf, tp[5]);
		ret = 0x00008000;
	}

	return ret;
}

static void npClose(const np_t *np)
{
	free(np->tbl);
}

int main(int argc, char *argv[])
{
	pbpHdr hdr;
	np_t np;
	int retv, i;
	char iso_name[64];
	uint64_t magic;
	uint32_t offset, size;
	void *data, *dec;
	FILE *in, *out;

	printf("NP Decryptor for PC. Writen by tpu.\n");
	kirk_init();

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

	retv = npOpen(&np, in, hdr.psar_offset);
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

	printf("ISO size: %zd MB\n", np.lbaSize * 2048 / 0x100000);

	out = fopen("NP.ISO", "wb");
	if(out == NULL){
		perror(iso_name);
		return errno;
	}

	for(i = 0; i < np.blkNum; i++){
		retv = npRead(&np, in, hdr.psar_offset, data, dec, i);
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
	npClose(&np);

	return 0;
}

