/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Probe (#111). See README.md.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV, CK_SLOT_ID, CK_SESSION_HANDLE, CK_FLAGS;
static CK_RV (*Initialize)(void*); static CK_RV (*OpenSession)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV (*Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV (*Logout)(CK_SESSION_HANDLE); static CK_RV (*CloseSession)(CK_SESSION_HANDLE);
static CK_RV (*Finalize)(void*);
static double ms(struct timespec a,struct timespec b){return (b.tv_sec-a.tv_sec)*1e3+(b.tv_nsec-a.tv_nsec)/1e6;}
#define NOW(v) struct timespec v; clock_gettime(CLOCK_MONOTONIC,&v)
int main(int argc, char **argv){
    (void)argc;
    void*h=dlopen(argv[1],RTLD_NOW); if(!h){fprintf(stderr,"%s\n",dlerror());return 2;}
    *(void**)&Initialize=dlsym(h,"C_Initialize"); *(void**)&OpenSession=dlsym(h,"C_OpenSession");
    *(void**)&Login=dlsym(h,"C_Login"); *(void**)&Logout=dlsym(h,"C_Logout");
    *(void**)&CloseSession=dlsym(h,"C_CloseSession"); *(void**)&Finalize=dlsym(h,"C_Finalize");
    const char*pin=getenv("FHSM_PIN");
    Initialize(NULL);
    CK_SESSION_HANDLE s=0; OpenSession(0,6,NULL,NULL,&s);

    NOW(a); CK_RV r1=Login(s,1,(CK_BYTE*)(size_t)pin,strlen(pin)); NOW(b);
    printf("  1re connexion, PIN correct ......... %7.2f ms  (rv=0x%lx)\n",ms(a,b),r1);
    Logout(s);
    NOW(c); Login(s,1,(CK_BYTE*)(size_t)pin,strlen(pin)); NOW(d);
    printf("  2e connexion, PIN correct .......... %7.2f ms\n",ms(c,d));
    Logout(s);
    NOW(e); Login(s,1,(CK_BYTE*)(size_t)pin,strlen(pin)); NOW(f);
    printf("  3e connexion, PIN correct .......... %7.2f ms\n",ms(e,f));
    Logout(s);

    const char*bad="mauvais-pin-xyz";
    NOW(g); CK_RV rb=Login(s,1,(CK_BYTE*)(size_t)bad,strlen(bad)); NOW(i);
    printf("  connexion avec un PIN FAUX ......... %7.2f ms  (rv=0x%lx)\n",ms(g,i),rb);
    NOW(j); Login(s,1,(CK_BYTE*)(size_t)bad,strlen(bad)); NOW(k);
    printf("  seconde tentative, PIN FAUX ........ %7.2f ms  (etranglement inclus)\n",ms(j,k));
    CloseSession(s); Finalize(NULL); return 0;
}
