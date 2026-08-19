# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Simorgh Labs
#
# Standalone on purpose: these probes load the module through dlopen, exactly
# as any PKCS#11 application would, and link nothing of ours. That is the
# point -- a measurement taken through the same door a client uses.
#
# Not reachable from the top-level Makefile: each needs a provisioned token
# with a composite key, which `make tests` does not have. See README.md.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE
LDLIBS   = -ldl -lpthread

PROBES = 01_latency 02_login_cost 03_login_shared 04_concurrency 05_session_race

all: $(PROBES)

# Named as a prerequisite because the loader lives there. The same omission in
# the top-level Makefile made a fix to tools/p11_util.h look as though it had
# not worked: the tools were never relinked.
$(PROBES): p11_probe.h

%: %.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(PROBES)

.PHONY: all clean
