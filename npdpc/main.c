/*
 * Copyright (C) 2011-2013 tpu
 * Copyright (C) 2015      173210 <root.3.173210@live.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "utils.h"

#include "kirk_engine.h"
#include "amctrl.h"

#include "pgd.c"
#include "tlzrc.c"

#define PBP_MAGIC htobe32(0x00504250) // "\0PBP"
#define NPUMDIMG_MAGIC htobe64(0x4E50554D44494D47) // "NPUMDIMG"
#define STARTDAT_MAGIC htobe64(0x5354415254444154) // "STARTDAT"

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

	if (*(uint64_t *)hdr != NPUMDIMG_MAGIC) {
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

	np->lbaStart = le32toh(*(uint32_t *)(hdr + 0x54));
	np->lbaEnd = le32toh(*(uint32_t *)(hdr + 0x64));
	np->lbaSize = np->lbaEnd - np->lbaStart + 1;

	np->blkSize = le32toh(*(uint32_t *)(hdr + 0x0c));
	np->blkNum = (np->lbaSize - 1) / np->blkSize;

	np->tblSize = np->blkNum * 32;
	np->tbl = malloc(np->tblSize);
	if (np->tbl == NULL)
		return -1;
	if (fseek(fp, offset + le32toh(*(uint32_t *)(hdr + 0x6C)), SEEK_SET))
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
		tp[4] = le32toh(tp[4] ^ tp[2] ^ tp[3]);
		tp[5] = le32toh(tp[5] ^ tp[1] ^ tp[2]);
		tp[6] = le32toh(tp[6] ^ tp[0] ^ tp[3]);
		tp[7] = le32toh(tp[7] ^ tp[0] ^ tp[1]);

		tp += 8;
	}

	return 0;
}

static int npRead(np_t *np, FILE *fp, uint32_t offset, void *data_buf, void *out_buf, int block)
{
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	int ret;
	uint32_t *tp;

	if (np == NULL || fp == NULL || data_buf == NULL || out_buf == NULL) {
		errno = EINVAL;
		return -1;
	}

	tp = (uint32_t *)(np->tbl + block * 32);
	if (tp[7]) {
		errno = EILSEQ;
		return -1;
	}

	if (fseek(fp, offset + tp[4], SEEK_SET))
		return -1;

	if (fread(data_buf, tp[5], 1, fp) <= 0)
		return -1;

	if (!(tp[6] & 1)) {
		sceDrmBBMacInit(&mkey, 3);
		sceDrmBBMacUpdate(&mkey, data_buf, tp[5]);
		ret = sceDrmBBMacFinal2(&mkey, tp, np->verKey);
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
	if (np == NULL)
		errno = EINVAL;
	else
		free(np->tbl);
}

static int dumpKeys(const np_t *np)
{
	int i;

	if (np == NULL) {
		errno = EINVAL;
		return -1;
	}

	printf("NPUMDIMG Version Key: 0x");
	for (i = 0; i < 16; i++)
		printf("%02X", np->verKey[i]);
	printf("\nNPUMDIMG Header Key:  0x");
	for (i = 0; i < 16; i++)
		printf("%02X", np->hdrKey[i]);
	putchar('\n');

	return 0;
}

static int dumpStartdat(FILE *in, uint32_t psp_offset, const char *inpath, const char *outpath)
{
	FILE *out;
	uint64_t magic;
	uint32_t size;
	void *buf;

	if (in == NULL || inpath == NULL || outpath == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (fseek(in, psp_offset + 1440, SEEK_SET)) {
		perror(inpath);
		return -1;
	}

	if (fread(&magic, sizeof(magic), 1, in) <= 0) {
		perror(inpath);
		return -1;
	}

	if (magic != STARTDAT_MAGIC)
		return 0;

	if (fseek(in, 12, SEEK_CUR)) {
		perror(inpath);
		return -1;
	}

	if (fread(&size, sizeof(size), 1, in) <= 0) {
		perror(inpath);
		return -1;
	}

	size = le32toh(size);

	buf = malloc(size);
	if (buf == NULL) {
		perror(NULL);
		return -1;
	}

	printf("Dumping STARTDAT...\n");
	if (fseek(in, 56, SEEK_CUR)) {
		perror(inpath);
		free(buf);
		return -1;
	}

	if (fread(buf, size, 1, in) <= 0) {
		perror(inpath);
		free(buf);
		return -1;
	}

	out = fopen(outpath, "wb");
	if (out == NULL) {
		perror(outpath);
		free(buf);
		return -1;
	}

	if (fwrite(buf, size, 1, out) != 1) {
		perror(outpath);
		free(buf);
		fclose(out);
		return -1;
	}

	if (fclose(out)) {
		perror(outpath);
		free(buf);
		fclose(out);
		return -1;
	}

	free(buf);

	return size;
}

static int dumpOpnssmp(FILE *in, uint32_t psp_offset, const void *verKey, const char *inpath, const char *outpath)
{
	FILE *out;
	uint32_t offset, size;
	void *buf;

	if (in == NULL || verKey == NULL || inpath == NULL || outpath == NULL) {
		errno = EINVAL;
		return -1;
	}

	if (fseek(in, psp_offset + 48, SEEK_SET)) {
		perror(inpath);
		return -1;
	}

	if (fread(&offset, sizeof(offset), 1, in) <= 0) {
		perror(inpath);
		return -1;
	}

	if (!offset)
		return 0;

	if (fread(&size, sizeof(size), 1, in) <= 0) {
		perror(inpath);
		return -1;
	}

	offset = le32toh(offset);
	size = le32toh(size);

	buf = malloc(size);
	if (buf == NULL) {
		perror(NULL);
		return -1;
	}

	printf("Dumping OPNSSMP...\n");
	if (fseek(in, offset, SEEK_SET)) {
		perror(inpath);
		free(buf);
		return -1;
	}

	if (fread(buf, size, 1, in) <= 0) {
		perror(inpath);
		free(buf);
		return -1;
	}

	size = pgd_decrypt(buf, size, 2, verKey);
	if (size < 0) {
		printf("PGD decryption failed 0x%08X\n", size);
		free(buf);
		return -1;
	}

	out = fopen(outpath, "wb");
	if (out == NULL) {
		perror(outpath);
		free(buf);
		return -1;
	}

	if (fwrite(buf, size, 1, out) <= 0) {
		perror(outpath);
		free(buf);
		fclose(out);
		return -1;
	}

	if (fclose(out)) {
		perror(outpath);
		free(buf);
		return -1;
	}

	free(buf);

	return size;
}

static int dumpNpumdimg(FILE *in, uint32_t psar_offset, np_t *np, const char *outpath)
{
	FILE *out;
	void *data, *dec;
	int i, ret;

	if (in == NULL || np == NULL || outpath == NULL) {
		errno = EINVAL;
		return -1;
	}

	data = malloc(np->blkSize * 2048);
	if (data == NULL) {
		perror(NULL);
		return -1;
	}

	dec = malloc(np->blkSize * 2048);
	if (dec == NULL) {
		perror(NULL);
		free(data);
		return -1;
	}

	out = fopen(outpath, "wb");
	if (out == NULL){
		perror(outpath);
		free(data);
		free(dec);
		return -1;
	}

	for (i = 0; i < np->blkNum; i++) {
		printf("Dumping NPUMDIMG... %3d%% %d/%d\r",
			i * 100 / np->blkNum, i, np->blkNum);

		ret = npRead(np, in, psar_offset, data, dec, i);
		if (ret <= 0) {
			printf("\nError %08X reading block %d\n", ret, i);
			free(data);
			free(dec);
			fclose(out);
			return ret;
		}

		if (fwrite(dec, ret, 1, out) != 1) {
			perror(outpath);
			free(data);
			free(dec);
			fclose(out);
			return -1;
		}
	}
	putchar('\n');

	if (fclose(out)) {
		perror(outpath);
		free(data);
		free(dec);
		return -1;
	}

	free(data);
	free(dec);

	return 0;
}

int main(int argc, char *argv[])
{
	pbpHdr hdr;
	np_t np;
	int ret;
	FILE *in;

	if (argc < 2) {
		printf("NP Decryptor for PC\n"
			" Copyright (C) 2011-2015 tpu, 173210\n"
			" This software is licensed under GPLv3.\n"
			"  usage: %s <EBOOT.PBP> [Ouput Directory]\n",
			argv[0]);
		return EINVAL;
	}

	kirk_init();

	in = fopen(argv[1], "rb");
	if(in == NULL) {
		perror(argv[1]);
		return errno;
	}

	if (fread(&hdr, sizeof(hdr), 1, in) <= 0) {
		perror(argv[1]);
		fclose(in);
		return errno;
	}

	if(hdr.magic != PBP_MAGIC) {
		printf("%s: Invalid PBP file.\n", argv[1]);
		fclose(in);
		return EILSEQ;
	}

	ret = npOpen(&np, in, hdr.psar_offset);
	if(ret < 0) {
		printf("%s: npOpen error %08x\n", argv[1], ret);
		fclose(in);
		return ret;
	}

	if (argc > 2)
		if (chdir(argv[2])) {
			perror(argv[2]);
			fclose(in);
			npClose(&np);
			return errno;
		}

	if (dumpKeys(&np) < 0) {
		fclose(in);
		npClose(&np);
		return errno;
	}

	if (dumpStartdat(in, hdr.psp_offset, argv[1], "STARTDAT.PNG") < 0) {
		fclose(in);
		npClose(&np);
		return errno;
	}

	if (dumpOpnssmp(in, hdr.psp_offset, np.verKey, argv[1], "OPNSSMP.BIN") < 0) {
		fclose(in);
		npClose(&np);
		return errno;
	}

	if (dumpNpumdimg(in, hdr.psar_offset, &np, "NPUMDIMG.ISO") < 0) {
		fclose(in);
		npClose(&np);
		return errno;
	}

	fclose(in);
	npClose(&np);
	return 0;
}
