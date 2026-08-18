/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Combien de clients simultanes tient le module, et ou ca coince ?
 * Deux modeles : une session par fil (le pool qu'un service tiendrait), et
 * une seule session partagee par tous (le cas ou le pool serait mal fait). */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>

typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV,CK_SLOT_ID,CK_SESSION_HANDLE,CK_OBJECT_HANDLE,CK_FLAGS;
typedef struct { CK_ULONG mechanism; void*p; CK_ULONG len; } CK_MECHANISM;
typedef struct { CK_ULONG type; void*pValue; CK_ULONG ulValueLen; } CK_ATTRIBUTE;

static CK_RV(*Init)(void*); static CK_RV(*Fin)(void*);
static CK_RV(*Open)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV(*Close)(CK_SESSION_HANDLE);
static CK_RV(*Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV(*FOInit)(CK_SESSION_HANDLE,CK_ATTRIBUTE*,CK_ULONG);
static CK_RV(*FO)(CK_SESSION_HANDLE,CK_OBJECT_HANDLE*,CK_ULONG,CK_ULONG*);
static CK_RV(*FOFin)(CK_SESSION_HANDLE);
static CK_RV(*SignInit)(CK_SESSION_HANDLE,CK_MECHANISM*,CK_OBJECT_HANDLE);
static CK_RV(*Sign)(CK_SESSION_HANDLE,CK_BYTE*,CK_ULONG,CK_BYTE*,CK_ULONG*);

static double ms(struct timespec a,struct timespec b){return (b.tv_sec-a.tv_sec)*1e3+(b.tv_nsec-a.tv_nsec)/1e6;}
#define NOW(v) struct timespec v; clock_gettime(CLOCK_MONOTONIC,&v)

static CK_OBJECT_HANDLE find_key(CK_SESSION_HANDLE s,const char*label){
    CK_ULONG cls=3;
    CK_ATTRIBUTE t[2]={{0,&cls,sizeof cls},{3,(void*)(size_t)label,(CK_ULONG)strlen(label)}};
    CK_OBJECT_HANDLE h=0; CK_ULONG n=0;
    if (FOInit(s, t, 2)) return 0;
    FO(s, &h, 1, &n);
    FOFin(s);
    return n ? h : 0;
}

static int K = 20;                 /* signatures par fil */
static int shared_mode = 0;
static CK_SESSION_HANDLE g_shared = 0;
static CK_OBJECT_HANDLE  g_key = 0;
static const char *g_pin, *g_label;
static pthread_barrier_t g_bar;
static double *g_lat;              /* toutes les latences, pour les centiles */

typedef struct { int id; } arg_t;

static void *worker(void *v){
    arg_t *a = v;
    CK_SESSION_HANDLE s = g_shared;
    CK_OBJECT_HANDLE k = g_key;
    if (!shared_mode) {
        Open(0,6,NULL,NULL,&s);
        Login(s,1,(CK_BYTE*)(size_t)g_pin,(CK_ULONG)strlen(g_pin));
        k = find_key(s,g_label);
    }
    CK_BYTE data[32]; memset(data,0x5A,sizeof data);
    static __thread CK_BYTE sig[8192];
    pthread_barrier_wait(&g_bar);
    for (int i=0;i<K;i++){
        CK_MECHANISM m={0x80004202,NULL,0}; CK_ULONG sl=sizeof sig;
        NOW(x); SignInit(s,&m,k); Sign(s,data,sizeof data,sig,&sl); NOW(y);
        g_lat[a->id*K+i]=ms(x,y);
    }
    if(!shared_mode) Close(s);
    return NULL;
}

static int cmpd(const void*p,const void*q){double a=*(const double*)p,b=*(const double*)q;return a<b?-1:a>b;}

static void run(int nthreads){
    g_lat = calloc((size_t)nthreads*K,sizeof *g_lat);
    pthread_barrier_init(&g_bar,NULL,(unsigned)nthreads);
    pthread_t *th=calloc((size_t)nthreads,sizeof *th);
    arg_t *ar=calloc((size_t)nthreads,sizeof *ar);
    NOW(a);
    for(int i=0;i<nthreads;i++){ar[i].id=i;pthread_create(&th[i],NULL,worker,&ar[i]);}
    for(int i=0;i<nthreads;i++)pthread_join(th[i],NULL);
    NOW(b);
    double tot=ms(a,b); int n=nthreads*K;
    qsort(g_lat,(size_t)n,sizeof *g_lat,cmpd);
    printf("  %2d fils : %7.1f sig/s   latence med %6.2f ms   p95 %6.2f ms   max %6.2f ms\n",
           nthreads, 1000.0*n/tot, g_lat[n/2], g_lat[(int)(n*0.95)], g_lat[n-1]);
    free(g_lat);free(th);free(ar);
    pthread_barrier_destroy(&g_bar);
}

int main(int argc, char **argv){
    (void)argc;
    void*h=dlopen(argv[1],RTLD_NOW); if(!h){fprintf(stderr,"%s\n",dlerror());return 2;}
    *(void**)&Init=dlsym(h,"C_Initialize");*(void**)&Fin=dlsym(h,"C_Finalize");
    *(void**)&Open=dlsym(h,"C_OpenSession");*(void**)&Close=dlsym(h,"C_CloseSession");
    *(void**)&Login=dlsym(h,"C_Login");*(void**)&FOInit=dlsym(h,"C_FindObjectsInit");
    *(void**)&FO=dlsym(h,"C_FindObjects");*(void**)&FOFin=dlsym(h,"C_FindObjectsFinal");
    *(void**)&SignInit=dlsym(h,"C_SignInit");*(void**)&Sign=dlsym(h,"C_Sign");
    g_pin=getenv("FHSM_PIN"); g_label=argv[2];
    Init(NULL);
    Open(0,6,NULL,NULL,&g_shared);
    Login(g_shared,1,(CK_BYTE*)(size_t)g_pin,(CK_ULONG)strlen(g_pin));
    g_key=find_key(g_shared,g_label);

    printf("\n  Une session par fil (le pool qu'un service tiendrait) :\n");
    shared_mode=0;
    for(int n=1;n<=8;n*=2) run(n);

    printf("\n  Une seule session partagee par tous les fils :\n");
    shared_mode=1;
    for(int n=1;n<=8;n*=2) run(n);

    Close(g_shared); Fin(NULL); return 0;
}
