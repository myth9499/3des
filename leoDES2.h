/** 
* auther :lilei
* email:soft1024@126.com
**/
#ifndef DESH
#define DESH

#include <string.h>


char szSubKeys[16][48];//����16��48λ��Կ
char szCiphertextRaw[64]; //�������������(64��Bits) int 0,1
char szPlaintextRaw[64]; //�������������(64��Bits) int 0,1
char szCiphertextInBytes[8];//����8λ����
char szPlaintextInBytes[8];//����8λ�����ַ���

char szCiphertextInBinary[65]; //�������������(64��Bits) char '0','1',���һλ��'\0'
char szCiphertextInHex[17]; //����ʮ����������,���һλ��'\0'
char szPlaintext[9];//����8λ�����ַ���,���һλ��'\0'

char szFCiphertextAnyLength[8192];//���ⳤ������
char szFPlaintextAnyLength[8192];//���ⳤ�������ַ���

//�๹�캯��
void leoDES2_Initialize(); 

//����:����16��28λ��key
//����:Դ8λ���ַ���(key)
//���:����������private CreateSubKey���������char SubKeys[16][48]
void leoDES2_InitializeKey(char* srcBytes);

//����:����8λ�ַ���
//����:8λ�ַ���
//���:���������ܺ��������private szCiphertext[16]
//      �û�ͨ������Ciphertext�õ�
void leoDES2_EncryptData(char* _srcBytes);

//����:����16λʮ�������ַ���
//����:16λʮ�������ַ���
//���:���������ܺ��������private szPlaintext[8]
//      �û�ͨ������Plaintext�õ�
void leoDES2_DecryptData(char* _srcBytes);

//����:�������ⳤ���ַ���
//����:���ⳤ���ַ���,����
//���:���������ܺ��������private szFCiphertextAnyLength[8192]
//      �û�ͨ������CiphertextAnyLength�õ�
void leoDES2_EncryptAnyLength(char* _srcBytes,unsigned int _bytesLength);

//����:�������ⳤ��ʮ�������ַ���
//����:���ⳤ���ַ���,����
//���:���������ܺ��������private szFPlaintextAnyLength[8192]
//      �û�ͨ������PlaintextAnyLength�õ�
void leoDES2_DecryptAnyLength(char* _srcBytes,unsigned int _bytesLength);

//����:Bytes��Bits��ת��,
//����:���任�ַ���,���������Ż�����ָ��,Bits��������С
void leoDES2_Bytes2Bits(char *srcBytes, char* dstBits, unsigned int sizeBits);

//����:Bits��Bytes��ת��,
//����:���任�ַ���,���������Ż�����ָ��,Bits��������С
void leoDES2_Bits2Bytes(char *dstBytes, char* srcBits, unsigned int sizeBits);

//����:Int��Bits��ת��,
//����:���任�ַ���,���������Ż�����ָ��
void leoDES2_Int2Bits(unsigned int srcByte, char* dstBits);
		
//����:Bits��Hex��ת��
//����:���任�ַ���,���������Ż�����ָ��,Bits��������С
void leoDES2_Bits2Hex(char *dstHex, char* srcBits, unsigned int sizeBits);
		
//����:Bits��Hex��ת��
//����:���任�ַ���,���������Ż�����ָ��,Bits��������С
void leoDES2_Hex2Bits(char *srcHex, char* dstBits, unsigned int sizeBits);

//szCiphertextInBinary��get����
char* leoDES2_GetCiphertextInBinary();

//szCiphertextInHex��get����
char* leoDES2_GetCiphertextInHex();

//Ciphertext��get����
char* leoDES2_GetCiphertextInBytes();

//Plaintext��get����
char* leoDES2_GetPlaintext();

//CiphertextAnyLength��get����
char* leoDES2_GetCiphertextAnyLength();

//PlaintextAnyLength��get����
char* leoDES2_GetPlaintextAnyLength();

//����:��������Կ
//����:����PC1�任��56λ�������ַ���
//���:��������char szSubKeys[16][48]
void leoDES2_CreateSubKey(char* sz_56key);

//����:DES�е�F����,
//����:��32λ,��32λ,key���(0-15)
//���:���ڱ任����32λ
void leoDES2_FunctionF(char* sz_Li,char* sz_Ri,unsigned int iKey);

//����:IP�任
//����:�������ַ���,����������ָ��
//���:�����ı�ڶ�������������
void leoDES2_InitialPermuteData(char* _src,char* _dst);

//����:����32λ������չλ48λ,
//����:ԭ32λ�ַ���,��չ�������ָ��
//���:�����ı�ڶ�������������
void leoDES2_ExpansionR(char* _src,char* _dst);

//����:�����,
//����:�����Ĳ����ַ���1,�ַ���2,����������,����������ָ��
//���: �����ı���ĸ�����������
void leoDES2_XOR(char* szParam1,char* szParam2, unsigned int uiParamLength, char* szReturnValueBuffer);

//����:S-BOX , ����ѹ��,
//����:48λ�������ַ���,
//���:���ؽ��:32λ�ַ���
void leoDES2_CompressFuncS(char* _src48, char* _dst32);

//����:IP��任,
//����:���任�ַ���,����������ָ��
//���:�����ı�ڶ�������������
void leoDES2_PermutationP(char* _src,char* _dst);


#endif
 
