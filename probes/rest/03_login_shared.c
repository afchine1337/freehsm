/* SPDX-License-Identifier: Apache-2.0
 * SPDX-FileCopyrightText: 2026 Simorgh Labs
 *
 * Probe (#111). See README.md.
 */
#include "p11_probe.h"

int main(int argc, char **argv){
    (void)argc;
    probe_load(argv[1]);
    const char*pin=getenv("FHSM_PIN");
    p11.Initialize(NULL);
    CK_SLOT_ID slot=probe_slot();
    CK_SESSION_HANDLE a=0,b=0;
    p11.OpenSession(slot,6,NULL,NULL,&a);
    printf("  session A : C_Login -> 0x%lx\n", p11.Login(a,1,(CK_BYTE*)(size_t)pin,strlen(pin)));
    /* a SECOND session, as a second REST request would open */
    p11.OpenSession(slot,6,NULL,NULL,&b);
    printf("  session B : C_Login -> 0x%lx   (0x100 = CKR_USER_ALREADY_LOGGED_IN)\n",
           p11.Login(b,1,(CK_BYTE*)(size_t)pin,strlen(pin)));
    /* Did B inherit A's role without having proved anything? */
    struct { CK_ULONG slot, state, flags, err; } si;
    memset(&si,0,sizeof si);
    if (p11.GetSessionInfo && p11.GetSessionInfo(b,&si)==0)
        printf("  session B : state=%lu  (3 or 4 = logged in as USER)\n", si.state);
    p11.CloseSession(a); p11.CloseSession(b); p11.Finalize(NULL); return 0;
}
