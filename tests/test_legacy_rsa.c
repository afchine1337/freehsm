/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * test_legacy_rsa.c --- Non-FIPS RSA legacy padding gating (#125).
 *
 *  RSA PKCS#1 v1.5 (0x01) and raw / X.509 (0x03) encryption are
 *  executable only in the all-mechanisms build, rejected under nist-approved-only.
 *  Profile-adaptive: generates an RSA-2048 keypair, then either
 *  round-trips both padding modes (interop) or asserts rejection
 *  (nist-approved-only, detected via C_GetMechanismList).
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
/* PKCS#11 v3.2 C.6.4.1 : pLabel is a fixed 32-byte field, blank-padded and
 * NOT NUL-terminated. Passing a short string literal made C_InitToken read
 * past it -- harmless in practice, which is why it survived until the suite
 * was first run under ASan (#125). */
static CK_BYTE *fhsm_pad_label(CK_BYTE buf[32], const char *s) {
    size_t n = strlen(s); if (n > 32) n = 32;
    memset(buf, ' ', 32); memcpy(buf, s, n);
    return buf;
}

int main(void){
  H=dlopen("./libfreehsm.so",RTLD_NOW);if(!H){fprintf(stderr,"%s\n",dlerror());return 2;}
  CK_RV(*I)(void*);SY(I,"C_Initialize");
  CK_RV(*IT)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);SY(IT,"C_InitToken");
  CK_RV(*OS)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);SY(OS,"C_OpenSession");
  CK_RV(*LI)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);SY(LI,"C_Login");
  CK_RV(*IP)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);SY(IP,"C_InitPIN");
  CK_RV(*GKP)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_ATTRIBUTE*,CK_ULONG,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*,CK_OBJECT_HANDLE*);SY(GKP,"C_GenerateKeyPair");
  CK_RV(*GML)(CK_SLOT_ID,CK_ULONG*,CK_ULONG*);SY(GML,"C_GetMechanismList");
  SY(EI,"C_EncryptInit");SY(EN,"C_Encrypt");SY(DI,"C_DecryptInit");SY(DE,"C_Decrypt");
  CK_RV(*SI)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);SY(SI,"C_SignInit");
  CK_RV(*SG)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);SY(SG,"C_Sign");
  CK_RV(*VI)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);SY(VI,"C_VerifyInit");
  CK_RV(*VE)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);SY(VE,"C_Verify");
  I(0);CK_BYTE so[]="00000000",us[]="user0000";IT(0,so,8,fhsm_pad_label((CK_BYTE[32]){0}, "t"));
  CK_SESSION_HANDLE s;OS(0,4|2,0,0,&s);LI(s,0,so,8);IP(s,us,8);LI(s,1,us,8);
  CK_ULONG mn=0;GML(0,0,&mn);CK_ULONG*ml=calloc(mn,sizeof(CK_ULONG));GML(0,ml,&mn);
  int strict=1;for(CK_ULONG i=0;i<mn;i++)if(ml[i]==0x1){strict=0;break;}free(ml);
  printf("test_legacy_rsa : profile = %s\n",strict?"nist-approved-only":"all-mechanisms");
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
  /* A ciphertext that is not modulus-sized (256 bytes for this 2048-bit key)
   * is refused with CKR_ENCRYPTED_DATA_LEN_RANGE (0x41), for both mechanisms
   * and on the size query as well as the real call. Until 2026-09-28 C_Decrypt
   * had no such check: a short input was taken as a smaller integer, implicit
   * rejection returned pseudo-random bytes, and the call said CKR_OK. The
   * unwrap path had the check all along. After each refusal the operation is
   * closed, so the next DI must succeed rather than return OPERATION_ACTIVE. */
  {
    CK_ULONG mechs[2]={0x1,0x3}; const char*names[2]={"RSA-PKCS","RSA-X509"};
    CK_BYTE shortct[255]; memset(shortct,0x5a,sizeof shortct);
    for(int k=0;k<2;k++){
      CK_MECHANISM m={mechs[k],0,0}; CK_BYTE pt[512]; CK_ULONG pl=512; CK_RV r;
      if((r=DI(s,&m,prv))){fprintf(stderr,"  FAIL %s DecInit 0x%lx\n",names[k],r);rc|=1;continue;}
      r=DE(s,shortct,255,NULL,&pl);
      if(r!=0x41UL){fprintf(stderr,"  FAIL %s size query on 255 bytes -> 0x%lx, want 0x41\n",names[k],r);rc|=1;continue;}
      if((r=DI(s,&m,prv))){fprintf(stderr,"  FAIL %s DecInit after refusal -> 0x%lx (op left open?)\n",names[k],r);rc|=1;continue;}
      pl=512; r=DE(s,shortct,255,pt,&pl);
      if(r!=0x41UL){fprintf(stderr,"  FAIL %s decrypt of 255 bytes -> 0x%lx, want 0x41\n",names[k],r);rc|=1;continue;}
      printf("  %s refuses a 255-byte ciphertext (0x41), query and call : OK\n",names[k]);
    }
  }
  /* SHA1-RSA-PKCS sign+verify */
  CK_MECHANISM sm={0x6,0,0};CK_BYTE smsg[32];for(int i=0;i<32;i++)smsg[i]=(CK_BYTE)i;
  CK_BYTE sig[512];CK_ULONG sl=512;
  if((rv=SI(s,&sm,prv))||(rv=SG(s,smsg,32,sig,&sl))||(rv=VI(s,&sm,pub))||(rv=VE(s,smsg,32,sig,sl))){
    fprintf(stderr,"  FAIL SHA1-RSA sign/verify 0x%lx\n",rv);rc|=1;
  } else printf("  SHA1-RSA sign+verify : OK\n");
  if(rc)return 1;
  printf("test_legacy_rsa : PASS\n");
  return 0;
}
