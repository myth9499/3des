/**
 * auther:lilei
 * email:bankll@126.com
 **/
#include <memory.h>
#include "leoDES2.h"


// permuted choice table (PC1)
const static char PC1_Table[56] = {
	57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};
// permuted choice key (PC2)
const static char PC2_Table[48] = {
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};
// number left rotations of pc1 
const static char Shift_Table[16] = {
	1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1
};
// initial permutation (IP)
const static char IP_Table[64] = {
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};
// expansion operation matrix (E)
const static char E_Table[48] = {
	32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
	8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};
// The (in)famous S-boxes 
const static char S_Box[8][4][16] = {
	// S1
	14,  4,	13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
	0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
	4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
	15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
	// S2 
	15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
	3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
	0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
	13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
	// S3 
	10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
	13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
	13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
	1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,
	// S4 
	7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
	13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
	10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
	3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,
	// S5 
	2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
	14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
	4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
	11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,
	// S6 
	12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
	10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
	9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
	4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,
	// S7 
	4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
	13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
	1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
	6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,
	// S8 
	13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
	1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
	7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
	2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
};
// 32-bit permutation function P used on the output of the S-boxes 
const static char P_Table[32] = {
	16, 7, 20, 21, 29, 12, 28, 17, 1,  15, 23, 26, 5,  18, 31, 10,
	2,  8, 24, 14, 32, 27, 3,  9,  19, 13, 30, 6,  22, 11, 4,  25
};
// final permutation IP^-1 
const static char IPR_Table[64] = {
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
};

void leoDES2_Initialize()
{
	memset(szCiphertextRaw,0,64);
	memset(szPlaintextRaw,0,64);
	memset(szCiphertextInBytes,0,8);
	memset(szPlaintextInBytes,0,8);
	memset(szCiphertextInBinary,0,65);
	memset(szCiphertextInHex,0,17);
	memset(szPlaintext,0,9);
	memset(szFCiphertextAnyLength,0,8192);
	memset(szCiphertextInHex,0,8192);
}

void leoDES2_InitializeKey(char* srcBytes)
{
	//convert 8 char-bytes key to 64 binary-bits
	char sz_64key[64] = {0};
	char sz_56key[56] = {0};
	int k=0;
	leoDES2_Bytes2Bits(srcBytes,sz_64key,64);
	//PC 1
	for(k=0;k<56;k++)
	{
		sz_56key[k] = sz_64key[PC1_Table[k]-1];
	}
	leoDES2_CreateSubKey(sz_56key);
}

void leoDES2_CreateSubKey(char* sz_56key)
{
	char szTmpL[28] = {0};
	char szTmpR[28] = {0};
	char szCi[28] = {0};
	char szDi[28] = {0};
	char szTmp56[56] = {0};
	int i=0,j=0;

	memcpy(szTmpL,sz_56key,28);
	memcpy(szTmpR,sz_56key + 28,28);

	for(i=0;i<16;i++)
	{
		//shift to left
		//Left 28 bits
		memcpy(szCi,szTmpL + Shift_Table[i],28 - Shift_Table[i]);
		memcpy(szCi + 28 - Shift_Table[i],szTmpL,Shift_Table[i]);
		//Right 28 bits
		memcpy(szDi,szTmpR + Shift_Table[i],28 - Shift_Table[i]);
		memcpy(szDi + 28 - Shift_Table[i],szTmpR,Shift_Table[i]);

		//permuted choice 48 bits key
		memcpy(szTmp56,szCi,28);
		memcpy(szTmp56 + 28,szDi,28);
		for(j=0;j<48;j++)
		{
			szSubKeys[i][j] = szTmp56[PC2_Table[j]-1];
		}
		//Evaluate new szTmpL and szTmpR
		memcpy(szTmpL,szCi,28);
		memcpy(szTmpR,szDi,28);
	}
}

void leoDES2_EncryptData(char* _srcBytes)
{
	char szSrcBits[64] = {0};
	char sz_IP[64] = {0};
	char sz_Li[32] = {0};
	char sz_Ri[32] = {0};
	char sz_Final64[64] = {0};
	int i=0,j=0;

	leoDES2_Bytes2Bits(_srcBytes,szSrcBits,64);
	//IP
	leoDES2_InitialPermuteData(szSrcBits,sz_IP);
	memcpy(sz_Li,sz_IP,32);
	memcpy(sz_Ri,sz_IP + 32,32);

	for(i=0;i<16;i++)
	{
		leoDES2_FunctionF(sz_Li,sz_Ri,i);
	}
	//so D=LR

	memcpy(sz_Final64,sz_Ri,32);
	memcpy(sz_Final64 + 32,sz_Li,32);

	//~IP
	for(j=0;j<64;j++)
	{
		szCiphertextRaw[j] = sz_Final64[IPR_Table[j]-1];
	}
	leoDES2_Bits2Bytes(szCiphertextInBytes,szCiphertextRaw,64);
}

void leoDES2_DecryptData(char* _srcBytes)
{
	char szSrcBits[64] = {0};
	char sz_IP[64] = {0};
	char sz_Li[32] = {0};
	char sz_Ri[32] = {0};
	char sz_Final64[64] = {0};
	int i=0,j=0;
	leoDES2_Bytes2Bits(_srcBytes,szSrcBits,64);
	//IP --- return is sz_IP
	leoDES2_InitialPermuteData(szSrcBits,sz_IP);
	//divide the 64 bits data to two parts
	memcpy(sz_Ri,sz_IP,32); //exchange L to R
	memcpy(sz_Li,sz_IP + 32,32);  //exchange R to L
	//16 rounds F and xor and exchange
	for(i=0;i<16;i++)
	{
		leoDES2_FunctionF(sz_Ri,sz_Li,15-i);
	}
	memcpy(sz_Final64,sz_Li,32);
	memcpy(sz_Final64 + 32,sz_Ri,32);
	// ~IP
	for(j=0;j<64;j++)
	{
		szPlaintextRaw[j] = sz_Final64[IPR_Table[j]-1];
	}
	leoDES2_Bits2Bytes(szPlaintextInBytes,szPlaintextRaw,64);
}

void leoDES2_FunctionF(char* sz_Li,char* sz_Ri,unsigned int iKey)
{
	char sz_48R[48] = {0};
	char sz_xor48[48] = {0};
	char sz_P32[32] = {0};
	char sz_Rii[32] = {0};
	char sz_Key[48] = {0};
	char s_Compress32[32] = {0};
	memcpy(sz_Key,szSubKeys[iKey],48);
	leoDES2_ExpansionR(sz_Ri,sz_48R);
	leoDES2_XOR(sz_48R,sz_Key,48,sz_xor48);

	leoDES2_CompressFuncS(sz_xor48,s_Compress32);
	leoDES2_PermutationP(s_Compress32,sz_P32);
	leoDES2_XOR(sz_P32,sz_Li,32,sz_Rii);
	memcpy(sz_Li,sz_Ri,32);
	memcpy(sz_Ri,sz_Rii,32);
}

void leoDES2_InitialPermuteData(char* _src,char* _dst)
{
	//IP
	int i=0;
	for(i=0;i<64;i++)
	{
		_dst[i] = _src[IP_Table[i]-1];
	}
}

void leoDES2_ExpansionR(char* _src,char* _dst)
{
	int i=0;
	for(i=0;i<48;i++)
	{
		_dst[i] = _src[E_Table[i]-1];
	}
}

void leoDES2_XOR(char* szParam1,char* szParam2, unsigned int uiParamLength, char* szReturnValueBuffer)
{
	unsigned int i=0;
	for(i=0; i<uiParamLength; i++)
	{
		szReturnValueBuffer[i] = szParam1[i] ^ szParam2[i];
	}
}

void leoDES2_CompressFuncS(char* _src48, char* _dst32)
{
	char bTemp[8][6]={0};
	char dstBits[4]={0};
	int i=0,iX=0,iY=0,j=0;

	for(i=0;i<8;i++)
	{
		memcpy(bTemp[i],_src48+i*6,6);
		iX = (bTemp[i][0])*2 + (bTemp[i][5]);
		iY = 0;
		for(j=1;j<5;j++)
		{
			iY += bTemp[i][j]<<(4-j);
		}
		leoDES2_Int2Bits(S_Box[i][iX][iY], dstBits);
		memcpy(_dst32 + i * 4, dstBits, 4);
	}

}

void leoDES2_PermutationP(char* _src,char* _dst)
{
	int i=0;
	for(i=0;i<32;i++)
	{
		_dst[i] = _src[P_Table[i]-1];
	}
}

void leoDES2_Bytes2Bits(char *srcBytes, char* dstBits, unsigned int sizeBits)
{
	unsigned int i=0;
	for(i=0; i < sizeBits; i++)
		dstBits[i] = ((srcBytes[i>>3]<<(i&7)) & 128)>>7;
}

void leoDES2_Bits2Bytes(char *dstBytes, char* srcBits, unsigned int sizeBits)
{
	unsigned int i=0;
	memset(dstBytes,0,sizeBits>>3);
	for(i=0; i < sizeBits; i++)
		dstBytes[i>>3] |= (srcBits[i] << (7 - (i & 7)));
}

void leoDES2_Int2Bits(unsigned int _src, char* dstBits)
{
	unsigned int i=0;
	for(i=0; i < 4; i++)
		dstBits[i] = ((_src<<i) & 8)>>3;
}

void leoDES2_Bits2Hex(char *dstHex, char* srcBits, unsigned int sizeBits)
{
	unsigned int i=0,j=0;
	memset(dstHex,0,sizeBits>>2);
	for(i=0; i < sizeBits; i++) //convert to int 0-15
		dstHex[i>>2] += (srcBits[i] << (3 - (i & 3)));
	for(j=0;j < (sizeBits>>2);j++)
		dstHex[j] += dstHex[j] > 9 ? 55 : 48; //convert to char '0'-'F'
}

void leoDES2_Hex2Bits(char *srcHex, char* dstBits, unsigned int sizeBits)
{
	unsigned int i=0,j=0;
	memset(dstBits,0,sizeBits);
	for(i=0;i < (sizeBits>>2);i++)
		srcHex[i] -= srcHex[i] > 64 ? 55 : 48; //convert to char int 0-15
	for(j=0; j < sizeBits; j++) 
		dstBits[j] = ((srcHex[j>>2]<<(j&3)) & 15) >> 3;

}

char* leoDES2_GetCiphertextInBinary()
{
	unsigned int i=0;
	for(i=0;i<64;i++)
	{
		szCiphertextInBinary[i] = szCiphertextRaw[i] + 48; // from int(0) to char('0') and int1 to char('1')
	}
	szCiphertextInBinary[64] = '\0';
	return szCiphertextInBinary;
}

char* leoDES2_GetCiphertextInHex()
{
	leoDES2_Bits2Hex(szCiphertextInHex,szCiphertextRaw,64);
	szCiphertextInHex[16] = '\0';
	return szCiphertextInHex;
}

char* leoDES2_GetCiphertextInBytes()
{
	return szCiphertextInBytes;
}

char* leoDES2_GetPlaintext()
{
	memcpy(szPlaintext,szPlaintextInBytes,8);
	szPlaintext[8] = '\0';
	return szPlaintext;
}

char* leoDES2_GetCiphertextAnyLength()
{
	return szFCiphertextAnyLength;
}

char* leoDES2_GetPlaintextAnyLength()
{
	return szFPlaintextAnyLength;
}

void leoDES2_EncryptAnyLength(char* _srcBytes,unsigned int _bytesLength)
{
	int iParts=0,iResidue=0,i=0;
	char szLast8Bits[8] = {0};

	/**lilei **/
	if(_bytesLength == 8)
	{
		leoDES2_EncryptData(_srcBytes);
		memcpy(szFCiphertextAnyLength,szCiphertextInBytes,8);
		//szFCiphertextAnyLength[8] = '\0';
		/** lilei  **/
		char _temp8bytes[8] = {0};
		int len;
		for(len=7;len>=0;len--)
		{
			_temp8bytes[len]=8;
		}
		leoDES2_EncryptData(_temp8bytes);
		int iParts = 1;
			memcpy(szFCiphertextAnyLength +(iParts<<3) ,szCiphertextInBytes,8);
			szFCiphertextAnyLength[((iParts+1)<<3)] = '\0';
		//memcpy(szFCiphertextAnyLength + 8,szCiphertextInBytes,8);
		//szFCiphertextAnyLength[16] = '\0';
		 /**lilei **/
		//szFCiphertextAnyLength[8] = '\0';
	}
	else if(_bytesLength < 8)
	{
		char _temp8bytes[8] = {0};
		memcpy(_temp8bytes,_srcBytes,_bytesLength);
		/** lilei **/
		int len=0;
		for(len=7;len>=_bytesLength;len--)
		{
			_temp8bytes[len]=8-_bytesLength;
		}
		/** lilei **/
		leoDES2_EncryptData(_temp8bytes);
		memcpy(szFCiphertextAnyLength,szCiphertextInBytes,8);
		szFCiphertextAnyLength[8] = '\0';
	}
	else if(_bytesLength > 8)
	{
		iParts = _bytesLength>>3;
		iResidue = _bytesLength % 8;

		for(i=0;i<iParts;i++)
		{
			memcpy(szLast8Bits,_srcBytes + (i<<3),8);
			leoDES2_EncryptData(szLast8Bits);
			memcpy(szFCiphertextAnyLength + (i<<3),szCiphertextInBytes,8);
		}
		memset(szLast8Bits,0,8);
		memcpy(szLast8Bits,_srcBytes + (iParts<<3),iResidue);

		/** lilei  **/
		if(iResidue == 0)
		{
			char _temp8bytes[8] = {0};
			int len;
			for(len=7;len>=0;len--)
			{
				//	memset(_temp8bytes,len,8-_bytesLength);
				_temp8bytes[len]=8;
			}
			leoDES2_EncryptData(_temp8bytes);
			memcpy(szFCiphertextAnyLength + (iParts<<3),szCiphertextInBytes,8);
			szFCiphertextAnyLength[((iParts+1)<<3)] = '\0';
		}else
		{
		/**/
			int len=0;
			for(len=7;len>=iResidue;len--)
			{
				//	memset(_temp8bytes,len,8-_bytesLength);
				szLast8Bits[len]=8-iResidue;
			}
			/** lilei **/
			leoDES2_EncryptData(szLast8Bits);
			memcpy(szFCiphertextAnyLength + (iParts<<3),szCiphertextInBytes,8);
			szFCiphertextAnyLength[((iParts+1)<<3)] = '\0';
		}
	}
}

void leoDES2_DecryptAnyLength(char* _srcBytes,unsigned int _bytesLength)
{
	int iParts=0,iResidue=0,i=0;
	char szLast8Bits[8] = {0};
	char _temp8bytes[8] = {0};

	if(_bytesLength == 8)
	{
		leoDES2_DecryptData(_srcBytes);
		memcpy(szFPlaintextAnyLength,szPlaintextInBytes,8);
		szFPlaintextAnyLength[8] = '\0';
	}
	else if(_bytesLength < 8)
	{
		memcpy(_temp8bytes,_srcBytes,8);
		leoDES2_DecryptData(_temp8bytes);
		memcpy(szFPlaintextAnyLength,szPlaintextInBytes,_bytesLength);
		szFPlaintextAnyLength[_bytesLength] = '\0';
	}
	else if(_bytesLength > 8)
	{
		iParts = _bytesLength>>3;
		iResidue = _bytesLength % 8;
		for(i=0;i<iParts;i++)
		{
			memcpy(szLast8Bits,_srcBytes + (i<<3),8);
			leoDES2_DecryptData(szLast8Bits);
			memcpy(szFPlaintextAnyLength + (i<<3),szPlaintextInBytes,8);
		}
		if(iResidue != 0)
		{
			memset(szLast8Bits,0,8);
			memcpy(szLast8Bits,_srcBytes + (iParts<<3),8);
			leoDES2_DecryptData(szLast8Bits);
			memcpy(szFPlaintextAnyLength + (iParts<<3),szPlaintextInBytes,iResidue);
		}
		szFPlaintextAnyLength[_bytesLength] = '\0';
	}
}
