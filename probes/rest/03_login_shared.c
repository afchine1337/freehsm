/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Probe (#111). See README.md.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef unsigned long CK_ULONG; typedef unsigned char CK_BYTE;
typedef CK_ULONG CK_RV,CK_SLOT_ID,CK_SESSION_HANDLE,CK_FLAGS;
static CK_RV(*Init)(void*);static CK_RV(*Open)(CK_SLOT_ID,CK_FLAGS,void*,void*,CK_SESSION_HANDLE*);
static CK_RV(*Login)(CK_SESSION_HANDLE,CK_ULONG,CK_BYTE*,CK_ULONG);
static CK_RV(*Close)(CK_SESSION_HANDLE);static CK_RV(*Fin)(void*);
static CK_RV(*GetSI)(CK_SESSION_HANDLE,void*);
int main(int argc, char **argv){
    (void)argc;
    void*h=dlopen(argv[1],RTLD_NOW);
    *(void**)&Init=dlsym(h,"C_Initialize");*(void**)&Open=dlsym(h,"C_OpenSession");
    *(void**)&Login=dlsym(h,"C_Login");*(void**)&Close=dlsym(h,"C_CloseSession");
    *(void**)&Fin=dlsym(h,"C_Finalize");*(void**)&GetSI=dlsym(h,"C_GetSessionInfo");
    const char*pin=getenv("FHSM_PIN");
    Init(NULL);
    CK_SESSION_HANDLE a=0,b=0;
    Open(0,6,NULL,NULL,&a);
    printf("  session A : C_Login -> 0x%lx\n", Login(a,1,(CK_BYTE*)(size_t)pin,strlen(pin)));
    /* une SECONDE session, comme le ferait une seconde requete REST */
    Open(0,6,NULL,NULL,&b);
    printf("  session B : C_Login -> 0x%lx   (0x100 = CKR_USER_ALREADY_LOGGED_IN)\n",
           Login(b,1,(CK_BYTE*)(size_t)pin,strlen(pin)));
    /* B a-t-elle herite du role de A sans avoir rien prouve ? */
    struct { CK_ULONG slot, state, flags, err; } si;
    memset(&si,0,sizeof si);
    if (GetSI && GetSI(b,&si)==0)
        printf("  session B : etat=%lu  (3 ou 4 = connectee en USER)\n", si.state);
    Close(a); Close(b); Fin(NULL); return 0;
}
