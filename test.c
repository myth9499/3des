#include <stdio.h>
#include <memory.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>


/**
DES_Encrypt(char *sourcefile,char *keyfile,char *destfile);
参数一:需要加密的原文件
参数二:可以自己定义的密钥
参数三:已加密的文件保存地址
DES_Decrypt(char *destfile,char *keyfile,char *sourcefile);
参数一:已加密的文件
参数二:可以自己定义的密钥,与加密的相同
参数三:明文文件存放地址
**/
char	fname[100];
char	delim[2] ; //分割字符串


int  main (int argc,char *argv[])
{

	int	ret;
	char	key[25];
	char	encryptstr[100];
	char	decryptstr[100];
	memset(fname,0x00,sizeof(fname));
	memset(key,0x00,sizeof(key));

	strcpy(key,"abcd1234efgh6789hijkmyth");
	if(argc!=4)
	{
		printf("请输入:程序名 E/D filename1  filename2\n");
		printf("E代表加密，filename1 为源文件 filename2 为目标密文\n");
		printf("D代表解密，filename1 为密文 filename2 为明文\n");
		return -1;
	}
	strcpy(fname,argv[0]);
	strcpy(delim," ");
	clock_t	a,b;
	printf("加解密标志:%s\n",argv[1]);
	if(!strcmp(argv[1],"E"))
	{
		printf("开始加密文件[%s]\n",argv[2]);
		clock_t a, b;
		a = clock ();
		ret =  de2enstr(fname,delim,key,argv[2],encryptstr);
		if(ret<0)
		{
			printf("加密文件失败,请检查格式是否正确\n");
			return -1;
		}
		b = clock ();
		printf ("加密消耗%ld微秒[%s]\n", b - a,encryptstr);
	}else
	{
		printf("开始解密文件[%s]\n",argv[2]);
		a = clock ();
		ret =  en2destr(fname,delim,key,argv[2],decryptstr);
		if(ret<0)
		{
			printf("解密文件失败,请检查格式是否正确\n");
			return -1;
		}
		b = clock ();
		printf ("解密消耗%ld微秒[%s]\n", b - a,decryptstr);
	}
	return 0;

}
