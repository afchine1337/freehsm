/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Are the signatures produced by N threads on ONE session valid?
 * Operation state is partitioned by session handle; sharing a handle between
 * threads means sharing that state. */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV,CK_SLOT_ID,CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_FLAGS;
typedef struct { CK_ULONG mechanism; void*p; CK_ULONG len; } CK_MECHANISM;
typedef struct { CK_ULONG type; void*pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;
static CK_RV(*Init)(void*);static CK_RV(*Fin)(void*);
static CK_RV(*Open)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV(*Close)(CK_SESSION_HANDLE);
static CK_RV(*Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV(*FOInit)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV(*FO)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE*,CK_ULONG,CK_ULONG*);
static CK_RV(*FOFin)(CK_SESSION_HANDLE);
static CK_RV(*SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV(*Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);
static CK_RV(*VerifyInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV(*Verify)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG);

static CK_SESSION_HANDLE g_s; static CK_OBJECT_HANDLE g_priv;
static pthread_barrier_t g_bar;
#define K 40
typedef struct { int id; int rv_bad; int len_bad; unsigned char data; } arg_t;

static void *w(void*v){
    arg_t*a=v; a->rv_bad=0; a->len_bad=0;
    CK_BYTE d[32]; memset(d,a->data,sizeof d);
    static __thread CK_BYTE sig[8192];
    pthread_barrier_wait(&g_bar);
    for(int i=0;i<K;i++){
        CK_MECHANISM m={0x80004202,NULL,0}; CK_ULONG sl=sizeof sig;
        CK_RV r1=SignInit(g_s,&m,g_priv);
        CK_RV r2=Sign(g_s,d,sizeof d,sig,&sl);
        if(r1||r2){a->rv_bad++;continue;}
        if(sl!=3373) a->len_bad++;         /* ML-DSA-65 3309 + Ed25519 64 */
    }
    return NULL;
}
int main(int argc, char **argv){
    (void)argc;
    void*h=dlopen(argv[1],RTLD_NOW);
    *(void**)&Init=dlsym(h,"C_Initialize");*(void**)&Fin=dlsym(h,"C_Finalize");
    *(void**)&Open=dlsym(h,"C_OpenSession");*(void**)&Close=dlsym(h,"C_CloseSession");
    *(void**)&Login=dlsym(h,"C_Login");*(void**)&FOInit=dlsym(h,"C_FindObjectsInit");
    *(void**)&FO=dlsym(h,"C_FindObjects");*(void**)&FOFin=dlsym(h,"C_FindObjectsFinal");
    *(void**)&SignInit=dlsym(h,"C_SignInit");*(void**)&Sign=dlsym(h,"C_Sign");
    *(void**)&VerifyInit=dlsym(h,"C_VerifyInit");*(void**)&Verify=dlsym(h,"C_Verify");
    const char*pin=getenv("FHSM_PIN");
    Init(NULL); Open(0,6,NULL,NULL,&g_s);
    Login(g_s,1,(CK_BYTE*)(size_t)pin,(CK_ULONG)strlen(pin));
    { CK_ULONG cls=3; CK_ATTRIBUTE t[2]={{0,&cls,sizeof cls},{3,argv[2],(CK_ULONG)strlen(argv[2])}};
      CK_ULONG n=0; FOInit(g_s,t,2); FO(g_s,&g_priv,1,&n); FOFin(g_s); }

    for (int N=1; N<=8; N*=2) {
        pthread_barrier_init(&g_bar,NULL,(unsigned)N);
        pthread_t th[8]; arg_t ar[8];
        for(int i=0;i<N;i++){ar[i].id=i;ar[i].data=(unsigned char)(0x10+i);pthread_create(&th[i],NULL,w,&ar[i]);}
        int rvb=0,lenb=0;
        for(int i=0;i<N;i++){pthread_join(th[i],NULL);rvb+=ar[i].rv_bad;lenb+=ar[i].len_bad;}
        printf("  %d thread(s) on ONE session : %3d operations, %d PKCS#11 errors, %d wrong lengths\n",
               N, N*K, rvb, lenb);
        pthread_barrier_destroy(&g_bar);
    }
    Close(g_s); Fin(NULL); return 0;
}
