#include <stdio.h>
#include <memory.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "leoDES2.h"


int SysLog(char	*type,char *format,...)
{
	FILE *fp = NULL;
	va_list argptr;
	int ret;
	char	logfile[1024];
	va_start(argptr,format);
	time_t  now;
	time(&now);
	struct tm *timenow;
	char	mon[3];
	char	day[3];
	char	logpath[1024];
	char	keyword[256];
	int		keylen;

	memset(logpath,0,sizeof(logpath));
	memset(keyword,0,sizeof(keyword));

	memset(mon,0,sizeof(mon));
	memset(day,0,sizeof(day));
	timenow = localtime(&now);

	if(1+(timenow->tm_mon)<10)
	{
		sprintf(mon,"0%d",1+(timenow->tm_mon));
	}else
	{
		sprintf(mon,"%d",1+(timenow->tm_mon));
	}
	if(timenow->tm_mday<10)
	{
		sprintf(day,"0%d",timenow->tm_mday);
	}else
	{
		sprintf(day,"%d",timenow->tm_mday);
	}
	if(get_cfg(logpath,keyword,&keylen,NULL)!=0)
	{
		printf("FILE [%s] LINE[%d] 打开配置文件[%s]失败,ERROR[%s]\n",__FILE__,__LINE__,"des.cfg",strerror(errno));	
		return -1;
	}
	//printf("!!!![%s] [%s] [%d]\n",logpath,keyword,keylen);
	if(!strcmp(type,"E"))
	{
		sprintf(logfile,"%s/%d%s%s_Encrypt.log",logpath,1900+(timenow->tm_year),mon,day);
	}else if(!strcmp(type,"D"))
	{
		sprintf(logfile,"%s/%d%s%s_Decrypt.log",logpath,1900+(timenow->tm_year),mon,day);
	}else if(!strcmp(type,"S"))
	{
		sprintf(logfile,"%s/sys_des.log","/tmp");
	}
	//printf("日志路径为:%s\n",logfile);
	fp = fopen(logfile,"a");
	if(fp == NULL)
	{
		perror("打开日志文件失败\n");
		return -1;
	}
	ret = vfprintf(fp,format,argptr);
	fclose(fp);
	va_end(argptr);
	return (ret);
}
int get_cfg(char	*logpath,char	*keyword,	int	*keylen,char	*fname)
{
	FILE	*fp;
	char	tmpstr[256];

	memset(tmpstr,0,sizeof(tmpstr));

	fp = fopen("des.cfg","r");
	if(fp == NULL)
	{
		printf("FILE [%s] LINE[%d] 打开配置文件[%s]失败,ERROR[%s]\n",__FILE__,__LINE__,"des.cfg",strerror(errno));	
		return -1;
	}
	while(fgets(tmpstr,sizeof(tmpstr),fp)!=NULL)
	{
		tmpstr[strlen(tmpstr)-1]='\0';
		if(tmpstr[0]=='#')
		{
			continue;
		}
		if(!strncmp(tmpstr,"LOGPATH",7))
		{
			if(logpath!=NULL)
			{
				strcpy(logpath,strstr(tmpstr,":")+1);
			}else
			{
				return -1;
			}
		}
		if(!strncmp(tmpstr,"KEYVALUE",8))
		{
			if(keyword!=NULL)
			{
				strcpy(keyword,strstr(tmpstr,":")+1);
			}
		}
		if(!strncmp(tmpstr,"KEYLEN",6))
		{
			if(keylen!=NULL)
			{
				*keylen=atoi(strstr(tmpstr,":")+1);
			}
		}
		if(!strncmp(tmpstr,"FUNCNAME",8))
		{
			if(fname!=NULL)
			{
				strcpy(fname,strstr(tmpstr,":")+1);
			}
		}
	}
	fclose(fp);
	return 0;
}
int	de2enfile(char	*fname,char	*delim,char	*key,char	*sfile,char	*encryfile)
{
	char szInputKey[8] = {0};
	char szInputPlaintext[1024] = {0};
	char szInputCiphertext[1024] = {0};
	char szInputCiphertextInHex[2048] = {0};
	char szCiphertextInBit[8196] = {0};
	int cmd = -1;
	int temp = 0;

	int	ret ;
	/** 根据原明文生成对应的密文 **/
	FILE	*sfilefp = NULL,*encryfp=NULL;
	char	tmpstr[4096];
	char	str[4096];
	char	encrystr[4096];
	char	encrystrtmp[10];
	/**
	  char	cardno[256];
	  char	passwd[256];
	  char	enddate[256];
	  char	seqno[256];
	  char	crname[256];
	 **/
	char	*cardno=NULL;
	char	*passwd=NULL;
	char	*enddate=NULL;
	char	*seqno=NULL;
	char	*crname=NULL;
	memset(tmpstr,0x00,sizeof(tmpstr));
	memset(str,0x00,sizeof(str));
	/**
	  memset(cardno,0x00,sizeof(cardno));
	  memset(passwd,0x00,sizeof(passwd));
	  memset(enddate,0x00,sizeof(enddate));
	  memset(seqno,0x00,sizeof(seqno));
	  memset(crname,0x00,sizeof(crname));
	 **/

	//strcpy(szInputKey,"88888888");

	sfilefp = fopen(sfile,"r");
	if(sfilefp ==NULL)
	{
		SysLog("E","Open file[%s] error\n",sfile);
		return -1;
	}
	encryfp = fopen(encryfile,"w");
	if(encryfp ==NULL)
	{
		SysLog("E","Open file[%s] error\n",encryfile);
		return -1;
	}
	while(fgets(tmpstr,sizeof(tmpstr),sfilefp)!=NULL)
	{
		tmpstr[strlen(tmpstr)-1]='\0';
		cardno = strtok(tmpstr,delim);
		if(cardno == NULL)
		{
			SysLog("E","解析cardno失败:%s\n",strerror(errno));
			fclose(sfilefp);
			fclose(encryfp);
			return -1;
		}
		passwd = strtok(NULL,delim);
		if(passwd == NULL)
		{
			SysLog("E","解析passwd失败:%s\n",strerror(errno));
			fclose(sfilefp);
			fclose(encryfp);
			return -1;
		}
		enddate = strtok(NULL,delim);
		if(enddate == NULL)
		{
			SysLog("E","解析enddate失败:%s\n",strerror(errno));
			fclose(sfilefp);
			fclose(encryfp);
			return -1;
		}
		/**
		  seqno = strtok(NULL,delim);
		  if(seqno == NULL)
		  {
		  SysLog("E","解析seqno失败:%s\n",strerror(errno));
		  fclose(sfilefp);
		  fclose(encryfp);
		  return -1;
		  }
		 **/
		crname = strtok(NULL,delim);
		if(crname == NULL)
		{
			SysLog("E","解析crname失败:%s\n",strerror(errno));
			fclose(sfilefp);
			fclose(encryfp);
			return -1;
		}
		/** 初始化所有数据 **/
		memset(szInputKey,0x00,sizeof(szInputKey));
		memset(szInputPlaintext,0x00,sizeof(szInputPlaintext));
		memset(szInputCiphertext,0x00,sizeof(szInputCiphertext));
		memset(szInputCiphertextInHex,0x00,sizeof(szInputCiphertextInHex));
		memset(szCiphertextInBit,0x00,sizeof(szCiphertextInBit));
		//printf("cardno is [%s]passwd is [%s] [%s] [%s] [%s]\n",cardno,passwd,enddate,seqno,crname);
		/** 第一次DES **/
		memcpy(szInputKey,key,8);
		leoDES2_InitializeKey(szInputKey);
		memset(encrystr,0x00,sizeof(encrystr));
		strcpy(szInputPlaintext,passwd);	
		temp = strlen(szInputPlaintext);
		leoDES2_EncryptAnyLength(szInputPlaintext,temp);
		if(temp%8==0)
		{
			temp=temp+8;
		}else
		{
			temp = temp % 8 == 0 ? temp : ((temp >> 3 ) + 1)  << 3;
		}
		memcpy(szInputCiphertext,leoDES2_GetCiphertextAnyLength(),temp);
		leoDES2_Bytes2Bits(szInputCiphertext,szCiphertextInBit,temp << 3);
		leoDES2_Bits2Hex(szInputCiphertextInHex,szCiphertextInBit,temp << 3);
		//szInputCiphertextInHex[temp % 8 == 0 ? temp << 1 : ((temp >> 3) + 1) << 4] = '\0';
		szInputCiphertextInHex[temp << 1] = 0;
		strcpy(encrystr,szInputCiphertextInHex);
		//printf("%s %d 第一次加密 [%s]\n",__FILE__,__LINE__,encrystr);
		/** 第二次des **/
		memcpy(szInputKey,key+8,8);
		leoDES2_InitializeKey(szInputKey);
		memset(szInputCiphertextInHex,0,2048);
		memset(szCiphertextInBit,0,8196);
		strcpy(szInputCiphertextInHex,encrystr);
		memset(encrystr,0x00,sizeof(encrystr));
		temp = strlen(szInputCiphertextInHex);
		leoDES2_Hex2Bits(szInputCiphertextInHex,szCiphertextInBit,temp << 2);
		leoDES2_Bits2Bytes(szInputCiphertext,szCiphertextInBit,temp << 2);
		leoDES2_DecryptAnyLength(szInputCiphertext,temp >> 1);
		strcpy(encrystr,leoDES2_GetPlaintextAnyLength());
		//printf("%s %d 第二次加密 [%s]\n",__FILE__,__LINE__,encrystr);
		/** 第三次 DES **/
		memcpy(szInputKey,key+16,8);
		leoDES2_InitializeKey(szInputKey);
		strcpy(szInputPlaintext,encrystr);	
		temp = strlen(szInputPlaintext);
		leoDES2_EncryptAnyLength(szInputPlaintext,temp);
		temp = temp % 8 == 0 ? temp : ((temp >> 3 ) + 1)  << 3;
		memcpy(szInputCiphertext,leoDES2_GetCiphertextAnyLength(),temp);
		leoDES2_Bytes2Bits(szInputCiphertext,szCiphertextInBit,temp << 3);
		leoDES2_Bits2Hex(szInputCiphertextInHex,szCiphertextInBit,temp << 3);
		//szInputCiphertextInHex[temp % 8 == 0 ? temp << 1 : ((temp >> 3) + 1) << 4] = '\0';
		szInputCiphertextInHex[temp << 1] = 0;
		memset(encrystr,0x00,sizeof(encrystr));
		strcpy(encrystr,szInputCiphertextInHex);
		printf("%s %d 第三次加密 [%s]\n",__FILE__,__LINE__,encrystr);
		sprintf(str,"%s %s %s %s",cardno,encrystr,enddate,crname);
		fwrite(str,strlen(str),1,encryfp);
		fwrite("\n",strlen("\n"),1,encryfp);
	}
	fclose(sfilefp);
	fclose(encryfp);
	return  0;
}
int	en2defile(char	*fname,char	*delim,char	*key,char	*encryfile,char	*sfile)
{
	char szInputKey[8] = {0};
	char szInputPlaintext[1024] = {0};
	char szInputCiphertext[1024] = {0};
	char szInputCiphertextInHex[2048] = {0};
	char szCiphertextInBit[8196] = {0};
	int cmd = -1;
	int temp = 0;

	int	ret ;
	/** 根据原密文生成对应的明文 **/
	FILE	*sfilefp = NULL,*encryfp=NULL;
	char	tmpstr[4096];
	char	str[4096];
	char	encrystr[4096];
	/**
	  char	cardno[256];
	  char	passwd[256];
	  char	enddate[256];
	  char	seqno[256];
	  char	crname[256];
	 **/
	char	*cardno=NULL;
	char	*passwd=NULL;
	char	*enddate=NULL;
	char	*seqno=NULL;
	char	*crname=NULL;
	memset(tmpstr,0x00,sizeof(tmpstr));
	memset(str,0x00,sizeof(str));
	/**
	  memset(cardno,0x00,sizeof(cardno));
	  memset(passwd,0x00,sizeof(passwd));
	  memset(enddate,0x00,sizeof(enddate));
	  memset(seqno,0x00,sizeof(seqno));
	  memset(crname,0x00,sizeof(crname));
	 **/

	// strcpy(szInputKey,"88888888");


	sfilefp = fopen(sfile,"w");
	if(sfilefp ==NULL)
	{
		SysLog("D","Open file[%s] error\n",sfile);
		return -1;
	}
	encryfp = fopen(encryfile,"r");
	if(encryfp ==NULL)
	{
		SysLog("D","Open file[%s] error\n",encryfile);
		return -1;
	}
	while(fgets(tmpstr,sizeof(tmpstr),encryfp)!=NULL)
	{
		tmpstr[strlen(tmpstr)-1]='\0';
		cardno = strtok(tmpstr,delim);
		if(cardno == NULL)
		{
			SysLog("D","解析cardno失败:%s\n",strerror(errno));
			fclose(sfilefp);
			fclose(encryfp);
			return -1;
		}
		passwd = strtok(NULL,delim);
		if(passwd == NULL)
		{
			SysLog("D","解析passwd失败:%s\n",strerror(errno));
			fclose(sfilefp);
			fclose(encryfp);
			return -1;
		}
		enddate = strtok(NULL,delim);
		if(enddate == NULL)
		{
			SysLog("D","解析enddate失败:%s\n",strerror(errno));
			fclose(sfilefp);
			fclose(encryfp);
			return -1;
		}
		/**
		  seqno = strtok(NULL,delim);
		  if(seqno == NULL)
		  {
		  SysLog("D","解析seqno失败:%s\n",strerror(errno));
		  fclose(sfilefp);
		  fclose(encryfp);
		  return -1;
		  }
		 **/
		crname = strtok(NULL,delim);
		if(crname == NULL)
		{
			SysLog("D","解析crname失败:%s\n",strerror(errno));
			fclose(sfilefp);
			fclose(encryfp);
			return -1;
		}

		//printf("cardno is [%s]passwd is [%s] [%s] [%s] [%s]\n",cardno,passwd,enddate,seqno,crname);
		/** 第一次解密 **/
		memset(szInputKey,0x00,sizeof(szInputKey));
		memset(szInputPlaintext,0x00,sizeof(szInputPlaintext));
		memset(szInputCiphertext,0x00,sizeof(szInputCiphertext));
		memset(szInputCiphertextInHex,0x00,sizeof(szInputCiphertextInHex));
		memset(szCiphertextInBit,0x00,sizeof(szCiphertextInBit));
		memset(encrystr,0x00,sizeof(encrystr));
		memset(szInputCiphertextInHex,0,2048);
		memset(szCiphertextInBit,0,8196);
		memcpy(szInputKey,key+16,8);
		leoDES2_InitializeKey(szInputKey);
		strcpy(szInputCiphertextInHex,passwd);
		temp = strlen(szInputCiphertextInHex);

		leoDES2_Hex2Bits(szInputCiphertextInHex,szCiphertextInBit,temp << 2);
		leoDES2_Bits2Bytes(szInputCiphertext,szCiphertextInBit,temp << 2);
		leoDES2_DecryptAnyLength(szInputCiphertext,temp >> 1);
		strcpy(encrystr,leoDES2_GetPlaintextAnyLength());
		//printf("After decrypt:\n%s\n\n\n", encrystr);
		//printf("%s %d 第一次解密 [%s]\n",__FILE__,__LINE__,encrystr);

		/** 第二次解密 **/
		memcpy(szInputKey,key+8,8);
		leoDES2_InitializeKey(szInputKey);
		memset(szInputCiphertextInHex,0,2048);
		memset(szCiphertextInBit,0,8196);
		strcpy(szInputPlaintext,encrystr);	
		memset(encrystr,0x00,sizeof(encrystr));
		temp = strlen(szInputPlaintext);
		leoDES2_EncryptAnyLength(szInputPlaintext,temp);
		temp = temp % 8 == 0 ? temp : ((temp >> 3 ) + 1)  << 3;
		memcpy(szInputCiphertext,leoDES2_GetCiphertextAnyLength(),temp);
		leoDES2_Bytes2Bits(szInputCiphertext,szCiphertextInBit,temp << 3);
		leoDES2_Bits2Hex(szInputCiphertextInHex,szCiphertextInBit,temp << 3);
		//szInputCiphertextInHex[temp % 8 == 0 ? temp << 1 : ((temp >> 3) + 1) << 4] = '\0';
		szInputCiphertextInHex[temp << 1] = 0;
		strcpy(encrystr,szInputCiphertextInHex);
		//printf("%s %d 第二次解密 [%s]\n",__FILE__,__LINE__,encrystr);

		/** 第三次解密 **/
		memcpy(szInputKey,key,8);
		leoDES2_InitializeKey(szInputKey);
		memset(szInputCiphertextInHex,0,2048);
		memset(szCiphertextInBit,0,8196);
		strcpy(szInputCiphertextInHex,encrystr);
		memset(encrystr,0x00,sizeof(encrystr));
		temp = strlen(szInputCiphertextInHex);
		leoDES2_Hex2Bits(szInputCiphertextInHex,szCiphertextInBit,temp << 2);
		leoDES2_Bits2Bytes(szInputCiphertext,szCiphertextInBit,temp << 2);
		leoDES2_DecryptAnyLength(szInputCiphertext,temp >> 1);
		strcpy(encrystr,leoDES2_GetPlaintextAnyLength());
		printf("%s %d 第三次解密 [%s]\n",__FILE__,__LINE__,encrystr);
		encrystr[strlen(encrystr)-encrystr[strlen(encrystr)-1]]='\0';

		memset(str,0x00,sizeof(str));
		//sprintf(str,"%s %s %s %s %s",cardno,encrystr,enddate,seqno,crname);
		sprintf(str,"%s %s %s %s",cardno,encrystr,enddate,crname);
		fwrite(str,strlen(str),1,sfilefp);
		fwrite("\n",strlen("\n"),1,sfilefp);
	}
	fclose(sfilefp);
	fclose(encryfp);
	return  0;
}
int	de2enstr(char	*fname,char	*delim,char	*key,char	*sfile,char	*encryfile)
{
	/** 检查key是否为24位 **/
	if(strlen(key)!=24)
	{
		SysLog("E","key 必须位24位 \n");
		return -1;
	}
	char szInputKey[8] = {0};
	char szInputPlaintext[1024] = {0};
	char szInputCiphertext[1024] = {0};
	char szInputCiphertextInHex[2048] = {0};
	char szCiphertextInBit[8196] = {0};
	int cmd = -1;
	int temp = 0;

	int	ret ;
	/** 根据原明文生成对应的密文 **/
	char	encrystr[4096];
	/** 初始化所有数据 **/
	memset(szInputKey,0x00,sizeof(szInputKey));
	memset(szInputPlaintext,0x00,sizeof(szInputPlaintext));
	memset(szInputCiphertext,0x00,sizeof(szInputCiphertext));
	memset(szInputCiphertextInHex,0x00,sizeof(szInputCiphertextInHex));
	memset(szCiphertextInBit,0x00,sizeof(szCiphertextInBit));
	//printf("cardno is [%s]passwd is [%s] [%s] [%s] [%s]\n",cardno,passwd,enddate,seqno,crname);
	/** 第一次DES **/
	memcpy(szInputKey,key,8);
	leoDES2_InitializeKey(szInputKey);
	memset(encrystr,0x00,sizeof(encrystr));
	strcpy(szInputPlaintext,sfile);	
	temp = strlen(szInputPlaintext);
	leoDES2_EncryptAnyLength(szInputPlaintext,temp);
	if(temp%8==0)
	{
		temp=temp+8;
	}else
	{
		temp = temp % 8 == 0 ? temp : ((temp >> 3 ) + 1)  << 3;
	}
	memcpy(szInputCiphertext,leoDES2_GetCiphertextAnyLength(),temp);
	leoDES2_Bytes2Bits(szInputCiphertext,szCiphertextInBit,temp << 3);
	leoDES2_Bits2Hex(szInputCiphertextInHex,szCiphertextInBit,temp << 3);
	//szInputCiphertextInHex[temp % 8 == 0 ? temp << 1 : ((temp >> 3) + 1) << 4] = '\0';
	szInputCiphertextInHex[temp << 1] = 0;
	strcpy(encrystr,szInputCiphertextInHex);
	//printf("%s %d 第一次加密 [%s]\n",__FILE__,__LINE__,encrystr);
	/** 第二次des **/
	memcpy(szInputKey,key+8,8);
	leoDES2_InitializeKey(szInputKey);
	memset(szInputCiphertextInHex,0,2048);
	memset(szCiphertextInBit,0,8196);
	strcpy(szInputCiphertextInHex,encrystr);
	memset(encrystr,0x00,sizeof(encrystr));
	temp = strlen(szInputCiphertextInHex);
	leoDES2_Hex2Bits(szInputCiphertextInHex,szCiphertextInBit,temp << 2);
	leoDES2_Bits2Bytes(szInputCiphertext,szCiphertextInBit,temp << 2);
	leoDES2_DecryptAnyLength(szInputCiphertext,temp >> 1);
	strcpy(encrystr,leoDES2_GetPlaintextAnyLength());
	//printf("%s %d 第二次加密 [%s]\n",__FILE__,__LINE__,encrystr);
	/** 第三次 DES **/
	memcpy(szInputKey,key+16,8);
	leoDES2_InitializeKey(szInputKey);
	strcpy(szInputPlaintext,encrystr);	
	temp = strlen(szInputPlaintext);
	leoDES2_EncryptAnyLength(szInputPlaintext,temp);
	temp = temp % 8 == 0 ? temp : ((temp >> 3 ) + 1)  << 3;
	memcpy(szInputCiphertext,leoDES2_GetCiphertextAnyLength(),temp);
	leoDES2_Bytes2Bits(szInputCiphertext,szCiphertextInBit,temp << 3);
	leoDES2_Bits2Hex(szInputCiphertextInHex,szCiphertextInBit,temp << 3);
	//szInputCiphertextInHex[temp % 8 == 0 ? temp << 1 : ((temp >> 3) + 1) << 4] = '\0';
	szInputCiphertextInHex[temp << 1] = 0;
	memset(encrystr,0x00,sizeof(encrystr));
	strcpy(encrystr,szInputCiphertextInHex);
	printf("%s %d 第三次加密 [%s]\n",__FILE__,__LINE__,encrystr);
	strcpy(encryfile,encrystr);
	return  0;
}
int	en2destr(char	*fname,char	*delim,char	*key,char	*encryfile,char	*sfile)
{
	/** 检查key是否为24位 **/
	if(strlen(key)!=24)
	{
		SysLog("D","key 必须位24位 \n");
		return -1;
	}
	char szInputKey[8] = {0};
	char szInputPlaintext[1024] = {0};
	char szInputCiphertext[1024] = {0};
	char szInputCiphertextInHex[2048] = {0};
	char szCiphertextInBit[8196] = {0};
	int cmd = -1;
	int temp = 0;

	int	ret ;
	/** 根据原密文生成对应的明文 **/
	char	str[4096];
	char	encrystr[4096];
	memset(str,0x00,sizeof(str));
	/** 第一次解密 **/
	memset(szInputKey,0x00,sizeof(szInputKey));
	memset(szInputPlaintext,0x00,sizeof(szInputPlaintext));
	memset(szInputCiphertext,0x00,sizeof(szInputCiphertext));
	memset(szInputCiphertextInHex,0x00,sizeof(szInputCiphertextInHex));
	memset(szCiphertextInBit,0x00,sizeof(szCiphertextInBit));
	memset(encrystr,0x00,sizeof(encrystr));
	memset(szInputCiphertextInHex,0,2048);
	memset(szCiphertextInBit,0,8196);
	memcpy(szInputKey,key+16,8);
	leoDES2_InitializeKey(szInputKey);
	strcpy(szInputCiphertextInHex,encryfile);
	temp = strlen(szInputCiphertextInHex);

	leoDES2_Hex2Bits(szInputCiphertextInHex,szCiphertextInBit,temp << 2);
	leoDES2_Bits2Bytes(szInputCiphertext,szCiphertextInBit,temp << 2);
	leoDES2_DecryptAnyLength(szInputCiphertext,temp >> 1);
	strcpy(encrystr,leoDES2_GetPlaintextAnyLength());
	//printf("After decrypt:\n%s\n\n\n", encrystr);
	//printf("%s %d 第一次解密 [%s]\n",__FILE__,__LINE__,encrystr);

	/** 第二次解密 **/
	memcpy(szInputKey,key+8,8);
	leoDES2_InitializeKey(szInputKey);
	memset(szInputCiphertextInHex,0,2048);
	memset(szCiphertextInBit,0,8196);
	strcpy(szInputPlaintext,encrystr);	
	memset(encrystr,0x00,sizeof(encrystr));
	temp = strlen(szInputPlaintext);
	leoDES2_EncryptAnyLength(szInputPlaintext,temp);
	temp = temp % 8 == 0 ? temp : ((temp >> 3 ) + 1)  << 3;
	memcpy(szInputCiphertext,leoDES2_GetCiphertextAnyLength(),temp);
	leoDES2_Bytes2Bits(szInputCiphertext,szCiphertextInBit,temp << 3);
	leoDES2_Bits2Hex(szInputCiphertextInHex,szCiphertextInBit,temp << 3);
	//szInputCiphertextInHex[temp % 8 == 0 ? temp << 1 : ((temp >> 3) + 1) << 4] = '\0';
	szInputCiphertextInHex[temp << 1] = 0;
	strcpy(encrystr,szInputCiphertextInHex);
	//printf("%s %d 第二次解密 [%s]\n",__FILE__,__LINE__,encrystr);

	/** 第三次解密 **/
	memcpy(szInputKey,key,8);
	leoDES2_InitializeKey(szInputKey);
	memset(szInputCiphertextInHex,0,2048);
	memset(szCiphertextInBit,0,8196);
	strcpy(szInputCiphertextInHex,encrystr);
	memset(encrystr,0x00,sizeof(encrystr));
	temp = strlen(szInputCiphertextInHex);
	leoDES2_Hex2Bits(szInputCiphertextInHex,szCiphertextInBit,temp << 2);
	leoDES2_Bits2Bytes(szInputCiphertext,szCiphertextInBit,temp << 2);
	leoDES2_DecryptAnyLength(szInputCiphertext,temp >> 1);
	strcpy(encrystr,leoDES2_GetPlaintextAnyLength());
	printf("%s %d 第三次解密 [%s]\n",__FILE__,__LINE__,encrystr);
	encrystr[strlen(encrystr)-encrystr[strlen(encrystr)-1]]='\0';

	memset(str,0x00,sizeof(str));
	//sprintf(str,"%s %s %s %s %s",cardno,encrystr,enddate,seqno,crname);
	strcpy(sfile,encrystr);
	return  0;
}
