#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
typedef unsigned long CK_ULONG,CK_RV,CK_SLOT_ID,CK_FLAGS,CK_SESSION_HANDLE,CK_OBJECT_HANDLE;
typedef unsigned char CK_BYTE;
typedef struct{CK_ULONG type;void*pValue;CK_ULONG ulValueLen;}CK_ATTRIBUTE;
typedef struct{CK_ULONG mechanism;void*p;CK_ULONG plen;}CK_MECHANISM;
#define CKR_MECHANISM_INVALID 0x70UL
/* Profile-adaptive : AES-ECB (0x1081) advertised iff interop. */
int main(void){
  void*h=dlopen("./libfreehsm-fips.so",RTLD_NOW);if(!h){fprintf(stderr,"%s\n",dlerror());return 2;}
  #define S(f,n) *(void**)&f=dlsym(h,n)
  CK_RV(*I)(void*);S(I,"C_Initialize");
  CK_RV(*IT)(CK_SLOT_ID,CK_BYTE*,CK_ULONG,CK_BYTE*);S(IT,"C_InitToken");
  CK_RV(*OS)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);S(OS,"C_OpenSession");
  CK_RV(*LI)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);S(LI,"C_Login");
  CK_RV(*IP)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG);S(IP,"C_InitPIN");
  CK_RV(*CO)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG,CK_OBJECT_HANDLE*);S(CO,"C_CreateObject");
  CK_RV(*EI)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);S(EI,"C_EncryptInit");
  CK_RV(*EN)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);S(EN,"C_Encrypt");
  CK_RV(*DI)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);S(DI,"C_DecryptInit");
  CK_RV(*DE)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);S(DE,"C_Decrypt");
  I(0);char so[]="00000000",us[]="user0000";IT(0,(CK_BYTE*)so,8,(CK_BYTE*)"t");
  CK_SESSION_HANDLE s;OS(0,4|2,0,0,&s);LI(s,0,(CK_BYTE*)so,8);IP(s,(CK_BYTE*)us,8);LI(s,1,(CK_BYTE*)us,8);
  CK_RV(*GML)(CK_SLOT_ID,CK_ULONG*,CK_ULONG*);S(GML,"C_GetMechanismList");
  CK_ULONG mn=0;GML(0,0,&mn);CK_ULONG*ml=calloc(mn,sizeof(CK_ULONG));GML(0,ml,&mn);
  int expect_reject=1;for(CK_ULONG i=0;i<mn;i++)if(ml[i]==0x1081){expect_reject=0;break;}free(ml);
  printf("test_legacy_cipher : profile = %s\n", expect_reject?"fips-strict":"interop");
  CK_ULONG cls=4,kt=0x1F;CK_BYTE key[16];for(int i=0;i<16;i++)key[i]=(CK_BYTE)i;
  CK_ATTRIBUTE t[]={{0,&cls,8},{0x100,&kt,8},{0x11,key,16}};
  CK_OBJECT_HANDLE ko=0;CK_RV rv=CO(s,t,3,&ko);if(rv){fprintf(stderr,"CreateObject 0x%lx\n",rv);return 2;}
  CK_MECHANISM m={0x1081,0,0}; /* CKM_AES_ECB */
  rv=EI(s,&m,ko);
  if(expect_reject){int ok=rv!=0;printf(ok?"  AES-ECB rejected (0x%lx) : OK\ntest_legacy_cipher : PASS\n":"  FAIL not rejected\n",rv);return ok?0:1;}
  if(rv){fprintf(stderr,"  EncryptInit 0x%lx\n",rv);return 1;}
  CK_BYTE pt[16];for(int i=0;i<16;i++)pt[i]=(CK_BYTE)(0x10+i);
  CK_BYTE ct[32];CK_ULONG cl=32;rv=EN(s,pt,16,ct,&cl);if(rv){fprintf(stderr,"  Encrypt 0x%lx\n",rv);return 1;}
  rv=DI(s,&m,ko);if(rv){fprintf(stderr,"  DecryptInit 0x%lx\n",rv);return 1;}
  CK_BYTE back[32];CK_ULONG bl=32;rv=DE(s,ct,cl,back,&bl);if(rv){fprintf(stderr,"  Decrypt 0x%lx\n",rv);return 1;}
  if(bl==16 && memcmp(back,pt,16)==0){printf("  AES-ECB round-trip : OK\ntest_legacy_cipher : PASS\n");return 0;}
  fprintf(stderr,"  FAIL round-trip mismatch (bl=%lu)\n",bl);return 1;
}
