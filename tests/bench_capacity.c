/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * tests/bench_capacity.c --- capacity micro-benchmark, not a test.
 *
 *  Answers "can FHSM_MAX_OBJECTS grow" with numbers instead of hope: cost of
 *  creating N objects, and cost of a worst-case (last-entry) lookup, which is
 *  the linear scan over object_count. Used to size 256 -> 1024.
 *
 *  Not run by the release pre-flight or the CI suite -- it takes seconds per
 *  run and measures rather than asserts.
 *
 *      make tests/bench_capacity && ./tests/bench_capacity 1024
 * ========================================================================= */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include "fhsm_token.h"
#include "fhsm_common.h"
static double ms(void){ struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e3 + (double)t.tv_nsec / 1e6; }
int main(int argc, char **argv){
  int N = argc>1 ? atoi(argv[1]) : 256;
  char dir[] = "/tmp/fhsm_b_XXXXXX";
  if (!mkdtemp(dir)) return 2;
  char path[512]; snprintf(path,sizeof path,"%s/t.tok",dir);
  fhsm_token_t *t=NULL;
  if (fhsm_token_init(path, "87654321", "bench", &t) != FHSM_RV_OK) return 2;
  (void)fhsm_token_login(t, FHSM_ROLE_SO, "87654321", strlen("87654321"));
  (void)fhsm_token_init_user_pin(t, "12345678");
  (void)fhsm_token_login(t, FHSM_ROLE_USER, "12345678", strlen("12345678"));
  static uint8_t key[1191];  /* taille d'une cle privee RSA-2048 */
  memset(key,0xA5,sizeof key);
  double t0=ms(); int made=0;
  for (int i = 0; i < N; i++) {
      uint32_t h = 0; char nm[32];
      snprintf(nm, sizeof nm, "k%04d", i);
      if (fhsm_token_object_add(t, 4, 0x1f, nm, key, sizeof key, NULL, 0,
                                FHSM_OBJF_SENSITIVE, &h) != FHSM_RV_OK) {
          break;
      }
      made++;
  }
  double t1=ms();
  /* cout d'un lookup : scan lineaire */
  const uint8_t *v; size_t vl; uint32_t c,kt;
  double t2 = ms();
  for (int r = 0; r < 10000; r++) {
      (void)fhsm_token_object_get(t, (uint32_t)made, &v, &vl, &c, &kt);
  }
  double t3=ms();
  printf("  N=%-5d  creation %7.0f ms (%5.2f ms/cle)   lookup pire cas %6.1f us\n",
         made, t1-t0, (t1-t0)/(made?made:1), (t3-t2)*1000.0/10000.0);
  fhsm_token_close(t); remove(path); rmdir(dir); return 0;
}
