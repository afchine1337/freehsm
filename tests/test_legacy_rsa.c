/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_legacy_rsa.c --- Non-FIPS RSA legacy padding gating (#125).
 *
 *  RSA PKCS#1 v1.5 (0x01) and raw / X.509 (0x03) encryption are
 *  executable only in the interop build, rejected under fips-strict.
 *  Profile-adaptive: generates an RSA-2048 keypair, then either
 *  round-trips both padding modes (interop) or asserts rejection
 *  (fips-strict, detected via C_GetMechanismList).
 * ========================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
typedef unsigned long CK_ULONG,CK_RV,CK_SLOT_ID,CK_FLAGS,CK_SESSION_HANDLE,CK_OBJECT_HANDLE;
typedef unsigned char CK_BYTE;
typedef struct{CK_ULONG type;void*pValue;CK_ULONG ulValueLen;}CK_ATTRIBUTE;
typedef struct{CK_ULONG mechanism;void*p;CK_ULONG plen;}CK_MECHANISM;
static void*H;
#define SY(f,n) *(void**)&f=dlsym(H,n)
static CK_RV(*EI)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV(*EN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV(*DI)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV(*DE)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static int rt(CK_SESSION_HANDLE s,CK_ULONG mech,CK_OBJECT_HANDLE pub,CK_OBJECT_HANDLE prv,CK_BYTE*msg,CK_ULONG mlen,const char*name){
  CK_MECHANISM m={mech,0,0};CK_RV rv=EI(s,&m,pub);
  if(rv){fprintf(stderr,"  FAIL %s EncInit 0x%lx\n",name,rv);return 1;}
  CK_BYTE ct[512];CK_ULONG cl=512;if((rv=EN(s,msg,mlen,ct,&cl))){fprintf(stderr,"  FAIL %s Enc 0x%lx\n",name,rv);return 1;}
  if((rv=DI(s,&m,prv))){fprintf(stderr,"  FAIL %s DecInit 0x%lx\n",name,rv);return 1;}
  CK_BYTE pt[512];CK_ULONG pl=512;if((rv=DE(s,ct,cl,pt,&pl))){fprintf(stderr,"  FAIL %s Dec 0x%lx\n",name,rv);return 1;}
  if(pl==mlen&&memcmp(pt,msg,mlen)==0){printf("  %s round-trip : OK\n",name);return 0;}
  fprintf(stderr,"  FAIL %s mismatch (pl=%lu)\n",name,pl);return 1;
}
int main(void){
  H=dlopen("./libfreehsm-fips.so",RTLD_NOW);if(!H){fprintf(stderr,"%s\n",dlerror());return 2;}
  CK_RV(*I)(void*);SY(I,"C_Initialize");
  CK_RV(*IT)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);SY(IT,"C_InitToken");
  CK_RV(*OS)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);SY(OS,"C_OpenSession");
  CK_RV(*LI)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);SY(LI,"C_Login");
  CK_RV(*IP)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);SY(IP,"C_InitPIN");
  CK_RV(*GKP)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);SY(GKP,"C_GenerateKeyPair");
  CK_RV(*GML)(CK_SLOT_ID,CK_ULONG*,CK_ULONG*);SY(GML,"C_GetMechanismList");
  SY(EI,"C_EncryptInit");SY(EN,"C_Encrypt");SY(DI,"C_DecryptInit");SY(DE,"C_Decrypt");
  I(0);CK_BYTE so[]="00000000",us[]="user0000";IT(0,so,8,(CK_BYTE*)"t");
  CK_SESSION_HANDLE s;OS(0,4|2,0,0,&s);LI(s,0,so,8);IP(s,us,8);LI(s,1,us,8);
  CK_ULONG mn=0;GML(0,0,&mn);CK_ULONG*ml=calloc(mn,sizeof(CK_ULONG));GML(0,ml,&mn);
  int strict=1;for(CK_ULONG i=0;i<mn;i++)if(ml[i]==0x1){strict=0;break;}free(ml);
  printf("test_legacy_rsa : profile = %s\n",strict?"fips-strict":"interop");
  CK_MECHANISM kg={0x0000,0,0};/*CKM_RSA_PKCS_KEY_PAIR_GEN*/
  CK_OBJECT_HANDLE pub=0,prv=0;CK_RV rv=GKP(s,&kg,0,0,0,0,&pub,&prv);
  if(rv){fprintf(stderr,"RSA keypair 0x%lx\n",rv);return 2;}
  if(strict){
    CK_MECHANISM m={0x1,0,0};
    if(EI(s,&m,pub)==0){fprintf(stderr,"  FAIL RSA-PKCS not rejected\n");return 1;}
    printf("  RSA-PKCS rejected : OK\ntest_legacy_rsa : PASS\n");return 0;
  }
  int rc=0;CK_BYTE msg[16];for(int i=0;i<16;i++)msg[i]=(CK_BYTE)(0x30+i);
  rc|=rt(s,0x1,pub,prv,msg,16,"RSA-PKCS");
  CK_BYTE raw[256];for(int i=0;i<256;i++)raw[i]=(CK_BYTE)(i&0x7f);raw[0]=0;
  rc|=rt(s,0x3,pub,prv,raw,256,"RSA-X509");
  if(rc)return 1;
  printf("test_legacy_rsa : PASS\n");
  return 0;
}
