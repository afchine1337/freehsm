/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * How many concurrent clients does the module take, and where does it bind?
 * Two models: one session per thread (the pool a service would hold), and one
 * session shared by all of them (the pool done wrong). */
#include "p11_probe.h"
#include <time.h>
#include <pthread.h>


static double ms(struct timespec a,struct timespec b){return (b.tv_sec-a.tv_sec)*1e3+(b.tv_nsec-a.tv_nsec)/1e6;}
#define NOW(v) struct timespec v; clock_gettime(CLOCK_MONOTONIC,&v)

static CK_OBJECT_HANDLE find_key(CK_SESSION_HANDLE s,const char*label){
    CK_ULONG cls=3;
    CK_ATTRIBUTE t[2]={{0,&cls,sizeof cls},{3,(void*)(size_t)label,(CK_ULONG)strlen(label)}};
    CK_OBJECT_HANDLE h=0; CK_ULONG n=0;
    if (p11.FindObjectsInit(s, t, 2)) return 0;
    p11.FindObjects(s, &h, 1, &n);
    p11.FindObjectsFinal(s);
    return n ? h : 0;
}

static int K = 20;                 /* signatures per thread */
static int shared_mode = 0;
static CK_SESSION_HANDLE g_shared = 0;
static CK_OBJECT_HANDLE  g_key = 0;
static const char *g_pin, *g_label;
static pthread_barrier_t g_bar;
static CK_SLOT_ID g_slot;
static double *g_lat;              /* every latency, for the percentiles */

typedef struct { int id; } arg_t;

static void *worker(void *v){
    arg_t *a = v;
    CK_SESSION_HANDLE s = g_shared;
    CK_OBJECT_HANDLE k = g_key;
    if (!shared_mode) {
        p11.OpenSession(g_slot,6,NULL,NULL,&s);
        p11.Login(s,1,(CK_BYTE*)(size_t)g_pin,(CK_ULONG)strlen(g_pin));
        k = find_key(s,g_label);
    }
    CK_BYTE data[32]; memset(data,0x5A,sizeof data);
    static __thread CK_BYTE sig[8192];
    pthread_barrier_wait(&g_bar);
    for (int i=0;i<K;i++){
        CK_MECHANISM m={0x80004202,NULL,0}; CK_ULONG sl=sizeof sig;
        NOW(x); p11.SignInit(s,&m,k); p11.Sign(s,data,sizeof data,sig,&sl); NOW(y);
        g_lat[a->id*K+i]=ms(x,y);
    }
    if(!shared_mode) p11.CloseSession(s);
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
    printf("  %2d threads : %7.1f sig/s   median %6.2f ms   p95 %6.2f ms   max %6.2f ms\n",
           nthreads, 1000.0*n/tot, g_lat[n/2], g_lat[(int)(n*0.95)], g_lat[n-1]);
    free(g_lat);free(th);free(ar);
    pthread_barrier_destroy(&g_bar);
}

int main(int argc, char **argv){
    (void)argc;
    probe_load(argv[1]);
    g_pin=getenv("FHSM_PIN"); g_label=argv[2];
    p11.Initialize(NULL);
    g_slot=probe_slot();
    p11.OpenSession(g_slot,6,NULL,NULL,&g_shared);
    p11.Login(g_shared,1,(CK_BYTE*)(size_t)g_pin,(CK_ULONG)strlen(g_pin));
    g_key=find_key(g_shared,g_label);

    printf("\n  One session per thread (the pool a service would hold):\n");
    shared_mode=0;
    for(int n=1;n<=8;n*=2) run(n);

    printf("\n  A single session shared by every thread:\n");
    shared_mode=1;
    for(int n=1;n<=8;n*=2) run(n);

    p11.CloseSession(g_shared); p11.Finalize(NULL); return 0;
}
