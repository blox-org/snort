/* $Id: twofish.h,v 2.1 2008/12/15 20:36:05 fknobbe Exp $
 *
 *
 * Copyright (C) 1997-2000 The Cryptix Foundation Limited.
 * Copyright (C) 2000 Farm9.
 * Copyright (C) 2001 Frank Knobbe.
 * All rights reserved.
 *
 * For Cryptix code:
 * Use, modification, copying and distribution of this software is subject
 * the terms and conditions of the Cryptix General Licence. You should have
 * received a copy of the Cryptix General Licence along with this library;
 * if not, you can download a copy from http://www.cryptix.org/ .
 *
 * For Farm9:
 * ---  jojo@farm9.com, August 2000, converted from Java to C++, added CBC mode and
 *      ciphertext stealing technique, added AsciiTwofish class for easy encryption
 *      decryption of text strings
 *
 * Frank Knobbe <frank@knobbe.us>:
 * ---  April 2001, converted from C++ to C, prefixed global variables
 *      with TwoFish, substituted some defines, changed functions to make use of
 *      variables supplied in a struct, modified and added routines for modular calls.
 *      Cleaned up the code so that defines are used instead of fixed 16's and 32's.
 *      Created two general purpose crypt routines for one block and multiple block
 *      encryption using Joh's CBC code.
 *		Added crypt routines that use a header (with a magic and data length).
 *		(Basically a major rewrite).
 *
 *      Note: Routines labeled _TwoFish are private and should not be used
 *      (or with extreme caution).
 *
 */

#ifndef __TWOFISH_LIBRARY_HEADER__
#define __TWOFISH_LIBRARY_HEADER__

#ifndef FALSE
#define FALSE	0
#endif
#ifndef TRUE
#define TRUE	!FALSE
#endif
#ifndef bool
#define bool	int
#endif


/* Constants */

#define TwoFish_DEFAULT_PW		"SnortHas2FishEncryptionRoutines!" /* default password (not more than 32 chars) */
#define TwoFish_MAGIC			"TwoFish"			/* to indentify a successful decryption */

enum
{	TwoFish_KEY_SIZE = 256,					/* Valid values: 64, 128, 192, 256 */
											/* User 256, other key sizes have not been tested. */
											/* (But should work. I substituted as much as */
											/* I could with this define.) */
	TwoFish_ROUNDS = 16,
	TwoFish_BLOCK_SIZE = 16,				/* bytes in a data-block */
	TwoFish_KEY_LENGTH = TwoFish_KEY_SIZE/8,	/* 32= 256-bit key */
	TwoFish_TOTAL_SUBKEYS = 4+4+2*TwoFish_ROUNDS,
	TwoFish_MAGIC_LEN = TwoFish_BLOCK_SIZE-8,
	TwoFish_SK_BUMP = 0x01010101,
	TwoFish_SK_ROTL = 9,
	TwoFish_P_00 = 1,
	TwoFish_P_01 = 0,
	TwoFish_P_02 = 0,
	TwoFish_P_03 = TwoFish_P_01 ^ 1,
	TwoFish_P_04 = 1,
	TwoFish_P_10 = 0,
	TwoFish_P_11 = 0,
	TwoFish_P_12 = 1,
	TwoFish_P_13 = TwoFish_P_11 ^ 1,
	TwoFish_P_14 = 0,
	TwoFish_P_20 = 1,
	TwoFish_P_21 = 1,
	TwoFish_P_22 = 0,
	TwoFish_P_23 = TwoFish_P_21 ^ 1,
	TwoFish_P_24 = 0,
	TwoFish_P_30 = 0,
	TwoFish_P_31 = 1,
	TwoFish_P_32 = 1,
	TwoFish_P_33 = TwoFish_P_31 ^ 1,
	TwoFish_P_34 = 1,
	TwoFish_GF256_FDBK =   0x169,
	TwoFish_GF256_FDBK_2 = 0x169 / 2,
	TwoFish_GF256_FDBK_4 = 0x169 / 4,
	TwoFish_RS_GF_FDBK = 0x14D,		/* field generator */
	TwoFish_MDS_GF_FDBK = 0x169		/* primitive polynomial for GF(256) */
};


/* Global data structure for callers */

typedef struct
{	u_int32_t sBox[4 * 256];					/* Key dependent S-box */
	u_int32_t subKeys[TwoFish_TOTAL_SUBKEYS];	/* Subkeys  */
	u_int8_t key[TwoFish_KEY_LENGTH];			/* Encryption Key */
	u_int8_t *output;							/* Pointer to output buffer */
	u_int8_t qBlockPlain[TwoFish_BLOCK_SIZE];	/* Used by CBC */
	u_int8_t qBlockCrypt[TwoFish_BLOCK_SIZE];
	u_int8_t prevCipher[TwoFish_BLOCK_SIZE];
	struct 				/* Header for crypt functions. Has to be at least one block long. */
	{	u_int32_t salt;							/* Random salt in first block (will salt the rest through CBC) */
		u_int8_t length[4];					/* The amount of data following the header */
		u_int8_t magic[TwoFish_MAGIC_LEN];		/* Magic to identify successful decryption  */
	}	header;
	bool qBlockDefined;
	bool dontflush;
}	TWOFISH;

#ifndef __TWOFISH_LIBRARY_SOURCE__

extern bool TwoFish_srand;					/* if set to TRUE (default), first call of TwoFishInit will seed rand();  */
											/* call of TwoFishInit */
#endif


/**** Public Functions ****/

/*	TwoFish Initialization
 *
 *	This routine generates a global data structure for use with TwoFish,
 *	initializes important values (such as subkeys, sBoxes), generates subkeys
 *	and precomputes the MDS matrix if not already done.
 *
 *	Input:	User supplied password (will be appended by default password of 'SnortHas2FishEncryptionRoutines!')
 *
 *  Output:	Pointer to TWOFISH structure. This data structure contains key dependent data.
 *			This pointer is used with all other crypt functions.
 */
TWOFISH *TwoFishInit(char *userkey);


/*	TwoFish Destroy
 *
 *	Nothing else but a free...
 *
 *	Input:	Pointer to the TwoFish structure.
 *
 */
void TwoFishDestroy(TWOFISH *tfdata);


/*	TwoFish Alloc
 *
 *	Allocates enough memory for the output buffer as required.
 *
 *	Input:	Length of the plaintext.
 *			Boolean flag for BinHex Output.
 *			Pointer to the TwoFish structure.
 *
 *	Output:	Returns a pointer to the memory allocated.
 */
void *TwoFishAlloc(unsigned long len,bool binhex,bool decrypt,TWOFISH *tfdata);


/*	TwoFish Free
 *
 *	Free's the allocated buffer.
 *
 *	Input:	Pointer to the TwoFish structure
 *
 *	Output:	(none)
 */
void TwoFishFree(TWOFISH *tfdata);


/*	TwoFish Set Output
 *
 *	If you want to allocate the output buffer yourself,
 *	then you can set it with this function.
 *
 *	Input:	Pointer to your output buffer
 *			Pointer to the TwoFish structure
 *
 *	Output:	(none)
 */
void TwoFishSetOutput(char *outp,TWOFISH *tfdata);


/*	TwoFish Raw Encryption
 *
 *	Does not use header, but does use CBC (if more than one block has to be encrypted).
 *
 *	Input:	Pointer to the buffer of the plaintext to be encrypted.
 *			Pointer to the buffer receiving the ciphertext.
 *			The length of the plaintext buffer.
 *			The TwoFish structure.
 *
 *	Output:	The amount of bytes encrypted if successful, otherwise 0.
 */
unsigned long TwoFishEncryptRaw(char *in,char *out,unsigned long len,TWOFISH *tfdata);

/*	TwoFish Raw Decryption
 *
 *	Does not use header, but does use CBC (if more than one block has to be decrypted).
 *
 *	Input:	Pointer to the buffer of the ciphertext to be decrypted.
 *			Pointer to the buffer receiving the plaintext.
 *			The length of the ciphertext buffer (at least one cipher block).
 *			The TwoFish structure.
 *
 *	Output:	The amount of bytes decrypted if successful, otherwise 0.
 */
unsigned long TwoFishDecryptRaw(char *in,char *out,unsigned long len,TWOFISH *tfdata);


/*	TwoFish Encryption
 *
 *	Uses header and CBC. If the output area has not been intialized with TwoFishAlloc,
 *  this routine will alloc the memory. In addition, it will include a small 'header'
 *  containing the magic and some salt. That way the decrypt routine can check if the
 *  packet got decrypted successfully, and return 0 instead of garbage.
 *
 *	Input:	Pointer to the buffer of the plaintext to be encrypted.
 *			Pointer to the pointer to the buffer receiving the ciphertext.
 *				The pointer either points to user allocated output buffer space, or to NULL, in which case
 *				this routine will set the pointer to the buffer allocated through the struct.
 *			The length of the plaintext buffer.
 *				Can be -1 if the input is a null terminated string, in which case we'll count for you.
 *			Boolean flag for BinHex Output (if used, output will be twice as large as input).
 *				Note: BinHex conversion overwrites (converts) input buffer!
 *			The TwoFish structure.
 *
 *	Output:	The amount of bytes encrypted if successful, otherwise 0.
 */
unsigned long TwoFishEncrypt(char *in,char **out,signed long len,bool binhex,TWOFISH *tfdata);


/*	TwoFish Decryption
 *
 *	Uses header and CBC. If the output area has not been intialized with TwoFishAlloc,
 *  this routine will alloc the memory. In addition, it will check the small 'header'
 *  containing the magic. If magic does not match we return 0. Otherwise we return the
 *  amount of bytes decrypted (should be the same as the length in the header).
 *
 *	Input:	Pointer to the buffer of the ciphertext to be decrypted.
 *			Pointer to the pointer to the buffer receiving the plaintext.
 *				The pointer either points to user allocated output buffer space, or to NULL, in which case
 *				this routine will set the pointer to the buffer allocated through the struct.
 *			The length of the ciphertext buffer.
 *				Can be -1 if the input is a null terminated binhex string, in which case we'll count for you.
 *			Boolean flag for BinHex Input (if used, plaintext will be half as large as input).
 *				Note: BinHex conversion overwrites (converts) input buffer!
 *			The TwoFish structure.
 *
 *	Output:	The amount of bytes decrypted if successful, otherwise 0.
 */
unsigned long TwoFishDecrypt(char *in,char **out,signed long len,bool binhex,TWOFISH *tfdata);


/**** Private Functions ****/

u_int8_t TwoFish__b(u_int32_t x,int n);
void _TwoFish_BinHex(u_int8_t *buf,unsigned long len,bool bintohex);
unsigned long _TwoFish_CryptRawCBC(char *in,char *out,unsigned long len,bool decrypt,TWOFISH *tfdata);
unsigned long _TwoFish_CryptRaw16(char *in,char *out,unsigned long len,bool decrypt,TWOFISH *tfdata);
unsigned long _TwoFish_CryptRaw(char *in,char *out,unsigned long len,bool decrypt,TWOFISH *tfdata);
void _TwoFish_PrecomputeMDSmatrix(void);
void _TwoFish_MakeSubKeys(TWOFISH *tfdata);
void _TwoFish_qBlockPush(u_int8_t *p,u_int8_t *c,TWOFISH *tfdata);
void _TwoFish_qBlockPop(u_int8_t *p,u_int8_t *c,TWOFISH *tfdata);
void _TwoFish_ResetCBC(TWOFISH *tfdata);
void _TwoFish_FlushOutput(u_int8_t *b,unsigned long len,TWOFISH *tfdata);
void _TwoFish_BlockCrypt(u_int8_t *in,u_int8_t *out,unsigned long size,int decrypt,TWOFISH *tfdata);
void _TwoFish_BlockCrypt16(u_int8_t *in,u_int8_t *out,bool decrypt,TWOFISH *tfdata);
u_int32_t _TwoFish_RS_MDS_Encode(u_int32_t k0,u_int32_t k1);
u_int32_t _TwoFish_F32(u_int32_t k64Cnt,u_int32_t x,u_int32_t *k32);
u_int32_t _TwoFish_Fe320(u_int32_t *lsBox,u_int32_t x);
u_int32_t _TwoFish_Fe323(u_int32_t *lsBox,u_int32_t x);
u_int32_t _TwoFish_Fe32(u_int32_t *lsBox,u_int32_t x,u_int32_t R);


#endif
