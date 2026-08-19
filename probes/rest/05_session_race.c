/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Are the signatures produced by N threads on ONE session valid?
 * Operation state is partitioned by session handle; sharing a handle between
 * threads means sharing that state. */
#include "p11_probe.h"
#include <pthread.h>


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
        CK_RV r1=p11.SignInit(g_s,&m,g_priv);
        CK_RV r2=p11.Sign(g_s,d,sizeof d,sig,&sl);
        if(r1||r2){a->rv_bad++;continue;}
        if(sl!=3373) a->len_bad++;         /* ML-DSA-65 3309 + Ed25519 64 */
    }
    return NULL;
}
int main(int argc, char **argv){
    (void)argc;
    probe_load(argv[1]);
    const char*pin=getenv("FHSM_PIN");
    p11.Initialize(NULL); p11.OpenSession(probe_slot(),6,NULL,NULL,&g_s);
    p11.Login(g_s,1,(CK_BYTE*)(size_t)pin,(CK_ULONG)strlen(pin));
    { CK_ULONG cls=3; CK_ATTRIBUTE t[2]={{0,&cls,sizeof cls},{3,argv[2],(CK_ULONG)strlen(argv[2])}};
      CK_ULONG n=0; p11.FindObjectsInit(g_s,t,2); p11.FindObjects(g_s,&g_priv,1,&n); p11.FindObjectsFinal(g_s); }

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
    p11.CloseSession(g_s); p11.Finalize(NULL); return 0;
}
