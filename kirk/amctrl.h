#ifndef AMCTRL_H
#define AMCTRL_H

typedef struct {
	int type;
	u8 key[16];
	u8 pad[16];
	int pad_size;
} MAC_KEY;

typedef struct
{
	u32 type;
	u32 seed;
	u8 key[16];
} CIPHER_KEY;

// type:
//      2: use fuse id
//      3: use fixed key. MAC need encrypt again
int sceDrmBBMacInit(MAC_KEY *mkey, int type);
int sceDrmBBMacUpdate(MAC_KEY *mkey, const void *buf, int size);
int sceDrmBBMacFinal(MAC_KEY *mkey, void *buf, const void *vkey);
int sceDrmBBMacFinal2(MAC_KEY *mkey, const void *out, const void *vkey);

int bbmac_build_final2(int type, void *mac);
int bbmac_getkey(MAC_KEY *mkey, const void *bbmac, void *vkey);
int bbmac_forge(MAC_KEY *mkey, const void *bbmac, const void *vkey, void *buf);

// type: 1 use fixed key
//       2 use fuse id
// mode: 1 for encrypt
//       2 for decrypt
int sceDrmBBCipherInit(CIPHER_KEY *ckey, int type, int mode, void *header_key, const void *version_key, u32 seed);
int sceDrmBBCipherUpdate(CIPHER_KEY *ckey, const void *data, int size);
int sceDrmBBCipherFinal(CIPHER_KEY *ckey);

// npdrm.prx
int sceNpDrmGetFixedKey(u8 *key, char *npstr, int type);

#endif
