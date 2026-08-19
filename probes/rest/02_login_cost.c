/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Probe (#111). See README.md.
 */
#include "p11_probe.h"
#include <time.h>

static double ms(struct timespec a,struct timespec b){return (b.tv_sec-a.tv_sec)*1e3+(b.tv_nsec-a.tv_nsec)/1e6;}
#define NOW(v) struct timespec v; clock_gettime(CLOCK_MONOTONIC,&v)
int main(int argc, char **argv){
    (void)argc;
    probe_load(argv[1]);
    const char*pin=getenv("FHSM_PIN");
    p11.Initialize(NULL);
    CK_SESSION_HANDLE s=0; p11.OpenSession(probe_slot(),6,NULL,NULL,&s);

    NOW(a); CK_RV r1=p11.Login(s,1,(CK_BYTE*)(size_t)pin,strlen(pin)); NOW(b);
    printf("  1st login, correct PIN ............. %7.2f ms  (rv=0x%lx)\n",ms(a,b),r1);
    p11.Logout(s);
    NOW(c); p11.Login(s,1,(CK_BYTE*)(size_t)pin,strlen(pin)); NOW(d);
    printf("  2nd login, correct PIN ............. %7.2f ms\n",ms(c,d));
    p11.Logout(s);
    NOW(e); p11.Login(s,1,(CK_BYTE*)(size_t)pin,strlen(pin)); NOW(f);
    printf("  3rd login, correct PIN ............. %7.2f ms\n",ms(e,f));
    p11.Logout(s);

    const char*bad="wrong-pin-xyz";
    NOW(g); CK_RV rb=p11.Login(s,1,(CK_BYTE*)(size_t)bad,strlen(bad)); NOW(i);
    printf("  login with a WRONG PIN ............. %7.2f ms  (rv=0x%lx)\n",ms(g,i),rb);
    NOW(j); p11.Login(s,1,(CK_BYTE*)(size_t)bad,strlen(bad)); NOW(k);
    printf("  second attempt, WRONG PIN .......... %7.2f ms  (throttle included)\n",ms(j,k));
    p11.CloseSession(s); p11.Finalize(NULL); return 0;
}
