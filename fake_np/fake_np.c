/*
 *  fake_np.c  -- make a fake NPdemo package
 *                written by tpu.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#include "kirk_engine.h"
#include "amctrl.h"

#include "isoreader.h"

/*************************************************************/

#define RATIO_LIMIT 90

int lzrc_compress(void *out, int out_len, void *in, int in_len);

static u8 zero_lz[0x50] = {
	0x05, 0xff, 0x80, 0x01, 0x0e, 0xd6, 0xe7, 0x37, 0x04, 0x3f, 0x53, 0x0b, 0xbc, 0xe7, 0xa3, 0x72, 
	0x14, 0xdc, 0x38, 0x8e, 0x0c, 0xaa, 0x94, 0x93, 0x46, 0xbf, 0xf8, 0x72, 0x15, 0x04, 0x7e, 0x9c, 
	0xe0, 0xec, 0x8b, 0x6c, 0x7d, 0xee, 0xf0, 0x7a, 0x90, 0x91, 0x0e, 0xb3, 0xc7, 0x8b, 0xd8, 0x08, 
	0x9d, 0x68, 0x09, 0xe5, 0x9e, 0xfe, 0x43, 0x03, 0x5b, 0x0b, 0x7c, 0x52, 0xe4, 0xfe, 0xfe, 0x66, 
	0x26, 0xe5, 0xcc, 0x83, 0xfc, 0x55, 0x16, 0xd2, 0x5e, 0x92, 0x00, 0x00, 0x8a, 0xed, 0x5e, 0x1a, 
};
static u8 zero_mac[16];
static int zero_lz_size = 0x50;

/*************************************************************/

u8 *load_file_from_ISO(const char *iso, char *name, int *size)
{
	int ret;
	u32 lba;
	u8 *buf;

	ret = isoOpen(iso);
	if (ret < 0) {
		return NULL;
	}

	ret = isoGetFileInfo(name, (u32*)size, &lba);
	if (ret < 0) {
		isoClose();
		return NULL;
	}

	buf = malloc(*size);
	if (buf == NULL) {
		isoClose();
		return NULL;
	}

	ret = isoRead(buf, lba, 0, *size);
	if (ret < 0) {
		isoClose();
		return NULL;
	}

	isoClose();
	return buf;
}

/*************************************************************/


#define PSF_MAGIC 0x46535000

typedef struct {
	u32 magic;
	u32 version;
	u32 key_offset;
	u32 val_offset;
	u32 key_count;
} SFO_Header;

typedef struct {
	u16 name_offset;
	u8  align;
	u8  type;
	u32 val_size;
	u32 align_size;
	u32 data_offset;
} SFO_Entry;

int sfo_getkey(u8 *sfo_buf, char *name, void *value)
{
	int i, offset;
	SFO_Header *sfo = (SFO_Header*)sfo_buf;
	SFO_Entry *sfo_keys = (SFO_Entry*)(sfo_buf+0x14);

	if(sfo->magic!=PSF_MAGIC)
		return -2;

	for(i=0; i<sfo->key_count; i++){
		offset = sfo_keys[i].name_offset;
		offset += sfo->key_offset;
		if(strcmp((char*)sfo_buf+offset, name)==0){
			offset = sfo_keys[i].data_offset;
			offset += sfo->val_offset;
			memcpy(value, sfo_buf+offset, sfo_keys[i].val_size);
			return sfo_keys[i].val_size;
		}
	}

	return -1;
}

int sfo_dump(u8 *sfo_buf)
{
	int i, offset;
	SFO_Header *sfo = (SFO_Header*)sfo_buf;
	SFO_Entry *sfo_keys = (SFO_Entry*)(sfo_buf+0x14);

	if(sfo->magic!=PSF_MAGIC)
		return -2;

	for(i=0; i<sfo->key_count; i++){
		offset = sfo_keys[i].name_offset;
		offset += sfo->key_offset;
		printf("%16s : ", sfo_buf+offset);

		offset = sfo_keys[i].data_offset;
		offset += sfo->val_offset;
		if(sfo_keys[i].type==2){
			printf("%s\n", sfo_buf+offset);
		}else if(sfo_keys[i].type==4){
			printf("%d\n", *(u32*)(sfo_buf+offset));
		}else{
			printf("%08x\n", *(u32*)(sfo_buf+offset));
		}
	}

	return 0;
}

/*************************************************************/

typedef struct {
	char name[16];
	u8 *param_sfo;
	int param_sfo_size;
	u8 *data_psp;
	int data_psp_size;
	u8 *np_header;

	char sys_ver[16];
	int max_size;
	int block_size;
	int total_block;
	u8 key[16];
}NPBASE;

int decrypt_base(NPBASE *npb)
{
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	u8 tmp_header[256];
	int start, end, lba_size, block_size, total_block;
	int retv;

	if(npb->max_size>0)
		return 0;

	// get version key
	sceDrmBBMacInit(&mkey, 3);
	sceDrmBBMacUpdate(&mkey, npb->np_header, 0xc0);
	bbmac_getkey(&mkey, npb->np_header+0xc0, npb->key);

	// header MAC check
	sceDrmBBMacInit(&mkey, 3);
	sceDrmBBMacUpdate(&mkey, npb->np_header, 0xc0);
	retv = sceDrmBBMacFinal2(&mkey, npb->np_header+0xc0, npb->key);
	if(retv){
		printf("NP header MAC check failed!\n");
		return -1;
	}

	// decrypt NP header
	memcpy(tmp_header, npb->np_header, 256);
	sceDrmBBCipherInit(&ckey, 1, 2, tmp_header+0xa0, npb->key, 0);
	sceDrmBBCipherUpdate(&ckey, tmp_header+0x40, 0x60);
	sceDrmBBCipherFinal(&ckey);

	block_size = *(u32*)(tmp_header+0x0c);
	start = *(u32*)(tmp_header+0x54);
	end   = *(u32*)(tmp_header+0x64);
	lba_size = end-start+1;
	total_block = (lba_size+block_size-1)/block_size;
	block_size *= 2048;

	npb->total_block = total_block;
	npb->block_size = block_size;
	npb->max_size = total_block*block_size;

	retv = sfo_getkey(npb->param_sfo, "DISC_ID", npb->name);
	if(retv<0)
		strcpy(npb->name, "Unknow");

	retv = sfo_getkey(npb->param_sfo, "PSP_SYSTEM_VER", npb->sys_ver);
	if(retv<0)
		strcpy(npb->sys_ver, "6.20");

	return 0;
}

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

NPBASE *load_base(char *filename)
{
	struct pbpHdr hdr;
	NPBASE *npb;
	FILE *fp;
	int retv;

	// Open and check PBP file
	fp = fopen(filename, "rb");
	if(fp == NULL) {
		printf("Open NP.PBP failed!\n");
		return NULL;
	}

	if (fread(&hdr, sizeof(hdr), 1, fp) <= 0)
		return NULL;
	if(hdr.magic != PBP_MAGIC) {
		printf("Not a valid PBP file!\n");
		return NULL;
	}

	// load NPBASE content
	npb = (NPBASE*)malloc(sizeof(NPBASE));
	if (npb == NULL)
		return NULL;
	memset(npb, 0, sizeof(NPBASE));

	npb->param_sfo_size = hdr.icon0_offset - hdr.param_offset;
	npb->data_psp_size = hdr.psar_offset - hdr.psp_offset;

	// load PARAM.SFO
	npb->param_sfo = malloc(npb->param_sfo_size);
	if (npb->param_sfo == NULL)
		return NULL;
	if (fseek(fp, hdr.param_offset, SEEK_SET))
		return NULL;
	if (fread(npb->param_sfo, npb->param_sfo_size, 1, fp) <= 0)
		return NULL;

	// load DATA.PSP
	npb->data_psp = malloc(npb->data_psp_size);
	if (fseek(fp, hdr.psp_offset, SEEK_SET))
		return NULL;
	if (fread(npb->data_psp, npb->data_psp_size, 1, fp) <= 0)
		return NULL;

	// load DATA.PSAR
	npb->np_header = malloc(256);
	if (fseek(fp, hdr.psar_offset, SEEK_SET))
		return NULL;
	if (fread(npb->np_header, 256, 1, fp) <= 0)
		return NULL;

	if (fclose(fp))
		perror("base: warning");

	if(strncmp((char*)npb->np_header, "NPUMDIMG", 8)){
		printf("DATA.PSAR isn't a NPUMDIMG!\n");
		free(npb);
		return NULL;
	}

	retv = decrypt_base(npb);
	if(retv)
		return NULL;

	return npb;
}

void save_base(NPBASE *np)
{
	FILE *fp;
	char name[64];
	u8 *pbp_header;
	int offset, header_size;

	header_size = 0x28;
	header_size += np->param_sfo_size;
	header_size += np->data_psp_size;
	header_size += 0x100;

	pbp_header = malloc(header_size+4096);
	memset(pbp_header, 0, header_size+4096);

	*(u32*)(pbp_header+0) = 0x50425000;
	*(u32*)(pbp_header+4) = 0x00010001;

	offset = 0x28;

	// param.sfo
	*(u32*)(pbp_header+0x08) = offset;
	memcpy(pbp_header+offset, np->param_sfo, np->param_sfo_size);
	offset += np->param_sfo_size;

	*(u32*)(pbp_header+0x0c) = offset;
	*(u32*)(pbp_header+0x10) = offset;
	*(u32*)(pbp_header+0x14) = offset;
	*(u32*)(pbp_header+0x18) = offset;
	*(u32*)(pbp_header+0x1c) = offset;

	// data.psp
	*(u32*)(pbp_header+0x20) = offset;
	memcpy(pbp_header+offset, np->data_psp, np->data_psp_size);
	offset += np->data_psp_size;

	// data.psar
	*(u32*)(pbp_header+0x24) = offset;
	memcpy(pbp_header+offset, np->np_header, 256);
	offset += 256;

	// write PBP file
	sprintf(name, "%s.PBP", np->name);
	printf("write %s ...\n", name);

	fp = fopen(name, "wb");
	fwrite(pbp_header, offset, 1, fp);
	fclose(fp);

	free(pbp_header);
}

/*************************************************************/


int write_pbp_part1(NPBASE *np, FILE *fp, char *iso_name)
{
	u8 *pbp_header;
	u8 *ico0_buf, *ico1_buf, *pic0_buf, *pic1_buf, *snd0_buf;
	int offset, header_size;
	int ico0_size, ico1_size, pic0_size, pic1_size, snd0_size;

	ico0_size = 0;
	ico1_size = 0;
	pic0_size = 0;
	pic1_size = 0;
	snd0_size = 0;

	ico0_buf = load_file_from_ISO(iso_name, "/PSP_GAME/ICON0.PNG", &ico0_size);
	if(ico0_buf==NULL)
		ico0_buf = load_file("ICON0.PNG", &ico0_size);

	ico1_buf = load_file_from_ISO(iso_name, "/PSP_GAME/ICON1.PMF", &ico1_size);
	if(ico1_buf==NULL)
		ico1_buf = load_file("ICON1.PMF", &ico1_size);

	pic0_buf = load_file_from_ISO(iso_name, "/PSP_GAME/PIC0.PNG",  &pic0_size);
	if(pic0_buf==NULL)
		pic0_buf = load_file("PIC0.PNG", &pic0_size);

	pic1_buf = load_file_from_ISO(iso_name, "/PSP_GAME/PIC1.PNG",  &pic1_size);
	if(pic1_buf==NULL)
		pic1_buf = load_file("PIC1.PNG", &pic1_size);

	snd0_buf = load_file_from_ISO(iso_name, "/PSP_GAME/SND0.AT3",  &snd0_size);
	if(snd0_buf==NULL)
		snd0_buf = load_file("SND0.AT3", &snd0_size);

	header_size = ico0_size+ico1_size+pic0_size+pic1_size+snd0_size;
	header_size += np->param_sfo_size;
	header_size += np->data_psp_size;
	pbp_header = malloc(header_size+4096);
	memset(pbp_header, 0, header_size+4096);

	*(u32*)(pbp_header+0) = 0x50425000;
	*(u32*)(pbp_header+4) = 0x00010001;

	offset = 0x28;

	printf("writing PARAM.SFO...\n");
	*(u32*)(pbp_header+0x08) = offset;
	memcpy(pbp_header+offset, np->param_sfo, np->param_sfo_size);
	offset += np->param_sfo_size;

	if(ico0_size)
		printf("writing ICON0.PNG...\n");
	*(u32*)(pbp_header+0x0c) = offset;
	memcpy(pbp_header+offset, ico0_buf, ico0_size);
	offset += ico0_size;

	if(ico1_size)
		printf("writing ICON1.PMF...\n");
	*(u32*)(pbp_header+0x10) = offset;
	memcpy(pbp_header+offset, ico1_buf, ico1_size);
	offset += ico1_size;

	if(pic0_size)
		printf("writing PIC0.PNG...\n");
	*(u32*)(pbp_header+0x14) = offset;
	memcpy(pbp_header+offset, pic0_buf, pic0_size);
	offset += pic0_size;

	if(pic1_size)
		printf("writing PIC1.PNG...\n");
	*(u32*)(pbp_header+0x18) = offset;
	memcpy(pbp_header+offset, pic1_buf, pic1_size);
	offset += pic1_size;

	if(snd0_size)
		printf("writing SND0.AT3...\n");
	*(u32*)(pbp_header+0x1c) = offset;
	memcpy(pbp_header+offset, snd0_buf, snd0_size);
	offset += snd0_size;

	printf("writing DATA.PSP...\n");
	*(u32*)(pbp_header+0x20) = offset;
	memcpy(pbp_header+offset, np->data_psp, np->data_psp_size);
	offset += np->data_psp_size;

	printf("writing DATA.PSAR...\n");
	*(u32*)(pbp_header+0x24) = offset;
	memcpy(pbp_header+offset, np->np_header, 256);
	offset += 256;

	fwrite(pbp_header, offset, 1, fp);

	return offset;
}

/*************************************************************/

void encrypt_table(u8 *table)
{
	u32 *p = (u32*)table;
	u32 k0, k1, k2, k3;

	k0 = p[0]^p[1];
	k1 = p[1]^p[2];
	k2 = p[0]^p[3];
	k3 = p[2]^p[3];

	p[4] ^= k3;
	p[5] ^= k1;
	p[6] ^= k2;
	p[7] ^= k0;
}

/*************************************************************/

int main(int argc, char *argv[])
{
	NPBASE *np_base;
	MAC_KEY mkey;
	CIPHER_KEY ckey;
	FILE *iso_fp, *pbp_fp;
	char *npb_name, *iso_name, *pbp_name;
	int i, ap, do_comp, do_save_base;
	int total_block, block_size;
	int iso_size, iso_offset, iso_block;
	int table_offset, table_size;
	u8 *iso_buf, *lzrc_buf, *table_buf;

	ap = 1;
	npb_name = NULL;
	iso_name = NULL;
	pbp_name = NULL;
	do_comp = 0;
	do_save_base = 0;
	np_base = NULL;

	// parameter process
	while(ap<argc){
		if(argv[ap][0]=='-'){
			switch (argv[ap][1]) {
				case 'b':
					ap++;
					if(ap >= argc)
						goto _help;
					npb_name = argv[ap];
					break;
				case 'c':
					do_comp = 1;
					break;
				case 'w':
					do_save_base = 1;
					break;
				default:
					goto _help;
			}
		}else{
			if(iso_name==NULL){
				iso_name = argv[ap];
			}else if(pbp_name==NULL){
				pbp_name = argv[ap];
			}
		}

		ap += 1;
	}

	if(iso_name==NULL)
		iso_name = "NP.ISO";
	if(pbp_name==NULL)
		pbp_name = "EBOOT.PBP";

	np_base = load_base(npb_name);
	if(np_base==NULL){
		printf("Load base %s faield!\n", npb_name);
		perror(NULL);
		goto _help;
	}
	if(do_save_base==1){
		save_base(np_base);
	}

	iso_fp = open_file(iso_name, &iso_size);
	if(iso_fp==NULL){
		printf("Open file %s faield!\n", iso_name);
		goto _help;
	}

	if(iso_size>np_base->max_size){
		printf("ISO is too big to fake! %d>%d\n", iso_size, np_base->max_size);
		goto _help;
	}

	// ready to fake!

	total_block = np_base->total_block;
	block_size  = np_base->block_size;
	iso_block = (iso_size+block_size-1)/block_size;
	
	// create PBP file
	pbp_fp = fopen(pbp_name, "wb");
	if(pbp_fp==NULL){
		printf("Create %s failed!\n", pbp_name);
		exit(-1);
	}


	// write pbp header and icon file
	table_offset = write_pbp_part1(np_base, pbp_fp, iso_name);

	// write empty table first.
	table_size = total_block*0x20;
	table_buf = malloc(table_size);
	memset(table_buf, 0, table_size);
	fwrite(table_buf, table_size, 1, pbp_fp);

	iso_offset = 256+table_size;

	iso_buf = malloc(block_size*2);
	lzrc_buf = malloc(block_size*2);

	// process iso block
	for(i=0; i<iso_block; i++){
		u8 *tb = table_buf+i*0x20;
		u8 *wbuf;
		int wsize, lzrc_size, ratio;

		if (fread(iso_buf, block_size, 1, iso_fp) <= 0) {
			perror(iso_name);
			return -1;
		}

		wbuf = iso_buf;
		wsize = block_size;

		if(do_comp==1){
			lzrc_size = lzrc_compress(lzrc_buf, block_size*2, iso_buf, block_size);
			memset(lzrc_buf+lzrc_size, 0, 16);
			ratio = (lzrc_size*100)/block_size;
			if(ratio<RATIO_LIMIT){
				wbuf = lzrc_buf;
				wsize = (lzrc_size+15)&~15;
			}
		}

		*(u32*)(tb+0x10) = iso_offset;
		*(u32*)(tb+0x14) = wsize;
		*(u32*)(tb+0x18) = 0;   // bit0=1: skip MAC check.
								// bit2=1: skip CIPHER encrypt
		*(u32*)(tb+0x1c) = 0;

		// encrypt block
		sceDrmBBCipherInit(&ckey, 1, 2, np_base->np_header+0xa0, np_base->key, iso_offset>>4);
		sceDrmBBCipherUpdate(&ckey, wbuf, wsize);
		sceDrmBBCipherFinal(&ckey);

		// generic MAC
		sceDrmBBMacInit(&mkey, 3);
		sceDrmBBMacUpdate(&mkey, wbuf, wsize);
		sceDrmBBMacFinal(&mkey, tb, np_base->key);
		bbmac_build_final2(3, tb);

		encrypt_table(tb);

		// write iso data
		if (fwrite(wbuf, wsize, 1, pbp_fp) != 1) {
			putchar('\n');
			perror(pbp_name);
			return -1;
		}

		// update offset
		iso_offset += wsize;
		printf("\rwriting iso block ... %02d%%", i*100/iso_block);
	}
	putchar('\n');

	// process remain block
	fwrite(zero_lz, zero_lz_size, 1, pbp_fp);
	sceDrmBBMacInit(&mkey, 3);
	sceDrmBBMacUpdate(&mkey, zero_lz, zero_lz_size);
	sceDrmBBMacFinal(&mkey, zero_mac, np_base->key);
	bbmac_build_final2(3, zero_mac);

	for(i=iso_block; i<total_block; i++){
		u8 *tb = table_buf+i*0x20;

		memcpy(tb, zero_mac, 16);

		*(u32*)(tb+0x10) = iso_offset;
		*(u32*)(tb+0x14) = zero_lz_size;
		*(u32*)(tb+0x18) = 0x00000004;
		*(u32*)(tb+0x1C) = 0;

		encrypt_table(tb);
	}
	iso_offset += zero_lz_size;

	fclose(iso_fp);
	fclose(pbp_fp);

	// crack the table hash
	sceDrmBBMacInit(&mkey, 3);
	sceDrmBBMacUpdate(&mkey, table_buf, table_size);
	bbmac_forge(&mkey, np_base->np_header+0xb0, np_base->key, table_buf+(table_size-0x10));

	// write lookup table again
	pbp_fp = fopen(pbp_name, "rb+");
	fseek(pbp_fp, table_offset, SEEK_SET);
	fwrite(table_buf, table_size, 1, pbp_fp);
	fclose(pbp_fp);
	return 0;

_help:
	printf("\n");
	printf("fake_np v1.0 by tpu\n");
	printf(" usage: fake_np [-b base_name] [-c] [-e] [iso_name] [pbp_name]\n");
	printf("    -b base_name: select a valid PSN game as base.\n");
	printf("    -w          : work with -b, save a small header of game.\n");
	printf("    -c          : compress data.\n");
//	printf("    -e          : encrypt data.\n");
	printf("    iso_name    : the game you want to fake. if empty, default as \"NP.ISO\".\n");
	printf("    pbp_name    : the fake result. if empty, default as \"EBOOT.PBP\".\n");
	printf("\n");

	return 0;
}

