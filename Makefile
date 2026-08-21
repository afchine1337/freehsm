# ===========================================================================
# Makefile --- FreeHSM C natif (FIPS 140-3 / CC EAL4+ candidate)
#
# Build targets:
#   make              # libfreehsm-fips.so + binaire de test
#   make tests        # exécute la suite KAT + tests d'audit
#   make integrity    # signe le .so et imprime le digest pour le module
#   make clean
#
# Compiler flags align with NIST recommendations for FIPS-validated
# crypto modules (NIST SP 800-67, hardening guidelines). All warnings
# are errors; the build fails on any unhandled return value, missing
# braces, signed-comparison, format-string mismatch, or implicit fall-
# through.
# ===========================================================================

CC          ?= cc
AR          ?= ar

# OpenSSL 3.x with FIPS provider --- override via OPENSSL_PREFIX if not
# installed in /usr/local/ssl.
OPENSSL_PREFIX ?= /usr/local/ssl
OPENSSL_LDFLAGS = -L$(OPENSSL_PREFIX)/lib64 -L$(OPENSSL_PREFIX)/lib \
                  -lcrypto -ldl -pthread
OPENSSL_CFLAGS  = -I$(OPENSSL_PREFIX)/include

WARN_FLAGS = \
    -Wall -Wextra -Wpedantic -Werror \
    -Wstrict-prototypes -Wshadow -Wpointer-arith -Wcast-align \
    -Wwrite-strings -Wnested-externs -Wmissing-prototypes \
    -Wmissing-declarations -Wredundant-decls -Wstrict-aliasing=2 \
    -Wformat=2 -Wformat-security -Wno-format-nonliteral \
    -Wnull-dereference -Wdouble-promotion -Wconversion \
    -Wno-sign-conversion -Wno-unused-parameter

HARDEN_FLAGS = \
    -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIC \
    -fstack-clash-protection -fcf-protection=full \
    -fvisibility=hidden -fno-strict-aliasing \
    -fno-omit-frame-pointer \
    -DOPENSSL_API_COMPAT=0x30000000L

# ---------------------------------------------------------------------------
# Reproducibility flags. Together with SOURCE_DATE_EPOCH (set by the
# Docker build environment), they purge every non-deterministic byte
# from the resulting .so :
#
#   -ffile-prefix-map  redacts absolute paths in __FILE__ / debug info
#   -fdebug-prefix-map idem for the DWARF .debug_info section. Both map
#                      $(CURDIR) to "." (NOT empty) : mapping to empty
#                      leaves the DWARF comp_dir (DW_AT_comp_dir, stored
#                      in .debug_line_str) as the absolute build path,
#                      which breaks cross-directory reproducibility on
#                      gcc < 12 (gcc 12+ has -fdebug-compilation-dir).
#                      Mapping to "." rewrites comp_dir to "." in every
#                      build tree, so two builds in different dirs are
#                      byte-identical.
#   -frandom-seed=fhsm makes gcc's anonymous-namespace / mangling stable
#   -Wno-builtin-macro-redefined needed because we override __FILE__
#   -D__DATE__='"redacted"' -D__TIME__='"redacted"' belt-and-braces
#                        in case SOURCE_DATE_EPOCH is missing
# ---------------------------------------------------------------------------
REPRO_FLAGS = \
    -ffile-prefix-map=$(CURDIR)=. \
    -fdebug-prefix-map=$(CURDIR)=. \
    -frandom-seed=fhsm-$(FHSM_VERSION_STRING) \
    -Wno-builtin-macro-redefined \
    -D__DATE__='"redacted"' -D__TIME__='"redacted"'

# Stable version string injected into REPRO_FLAGS. Parsed from the
# canonical header so a release bump propagates automatically.
FHSM_VERSION_STRING := $(shell awk -F'"' '/FHSM_VERSION_STRING/{print $$2; exit}' include/fhsm_common.h)

DEBUG_FLAGS ?= -g3 -O2

# SANITIZE=1 builds with AddressSanitizer + UBSan. Off by default; the hardening
# flags and the sanitizers do not coexist well (ASan replaces the allocator that
# _FORTIFY_SOURCE instruments) so the hardening set is dropped for this build.
# Never ship a SANITIZE build -- it is for the store-format and parser work,
# where a bounds bug does not show up as a failing test but as an unreadable
# token months later.
#   make SANITIZE=1 && make SANITIZE=1 tests/test_token
# TSAN=1 builds with ThreadSanitizer. Separate from SANITIZE=1 because ASan and
# TSan cannot coexist in one binary.
#
# Added for #111-prep. PKCS#11's model is one process per application, so the
# absence of locking in fhsm_pkcs11.c is harmless today; a REST server inverts
# that and makes g_op_*, g_slots and g_finds shared mutable state. TSan is to
# concurrency what SANITIZE=1 was to memory in #125 -- it finds what review does
# not. Never ship a TSAN build.
#   make TSAN=1 && make TSAN=1 tests/test_concurrency
ifeq ($(TSAN),1)
SAN_FLAGS    = -fsanitize=thread -fno-omit-frame-pointer
HARDEN_FLAGS = -fPIC -fvisibility=hidden -fno-strict-aliasing \
               -DOPENSSL_API_COMPAT=0x30000000L
DEBUG_FLAGS  = -g3 -O1
endif

ifeq ($(SANITIZE),1)
SAN_FLAGS   = -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all
# _FORTIFY_SOURCE instruments the allocator ASan replaces, so the hardening set
# is dropped -- but -fPIC and -fvisibility are structural, not hardening, and
# the shared object does not link without them.
HARDEN_FLAGS = -fPIC -fvisibility=hidden -fno-strict-aliasing \
               -DOPENSSL_API_COMPAT=0x30000000L
DEBUG_FLAGS  = -g3 -O1
endif

CFLAGS  = $(WARN_FLAGS) $(HARDEN_FLAGS) $(SAN_FLAGS) $(REPRO_FLAGS) $(DEBUG_FLAGS) \
          -std=c11 -D_GNU_SOURCE \
          -Iinclude $(OPENSSL_CFLAGS) $(EXTRA_CFLAGS)

# Linker reproducibility :
#   --build-id=none        suppress the random .note.gnu.build-id slot
#   --hash-style=gnu       deterministic hash table layout
#   --sort-common          stable .bss/.common ordering
#   --reproducible         ld >= 2.38 honors the bundle (binutils 2.38+)
LDFLAGS = $(SAN_FLAGS) -Wl,-z,relro,-z,now,-z,noexecstack,-z,defs \
          -Wl,--no-undefined \
          -Wl,--build-id=none \
          -Wl,--hash-style=gnu \
          -Wl,--sort-common \
          $(OPENSSL_LDFLAGS)

# ---------------------------------------------------------------------------
# Sources / objects
# ---------------------------------------------------------------------------
LIB_SRC = \
    src/fhsm_state.c                  \
    src/fhsm_memory.c                 \
    src/fhsm_crypto.c                 \
    src/fhsm_audit.c                  \
    src/fhsm_pkcs11.c                 \
    src/fhsm_ecdsa_raw.c              \
    src/fhsm_pq_params.c              \
    src/fhsm_create_attrs.c           \
    src/fhsm_token.c                  \
    src/fhsm_session.c                \
    src/fhsm_integrity.c              \
    src/fhsm_pairwise.c               \
    src/fhsm_composite.c              \
    src/fhsm_drbg.c                   \
    src/fhsm_tpm.c                    \
    src/fhsm_token_tpm.c              \
    src/fhsm_mode.c                   \
    src/fhsm_conf.c                   \
    src/dispatch/fhsm_dispatch_legacy.c \
    src/gen/fhsm_dispatch.c           \
    src/dispatch/fhsm_dispatch_common.c \
    src/dispatch/fhsm_dispatch_digest.c \
    src/dispatch/fhsm_dispatch_hmac.c \
    src/dispatch/fhsm_dispatch_aes.c  \
    src/dispatch/fhsm_dispatch_kdf.c  \
    src/dispatch/fhsm_dispatch_pkey.c \
    src/dispatch/fhsm_dispatch_pq.c   \
    src/dispatch/fhsm_dispatch_kmac.c   \
    src/dispatch/fhsm_dispatch_concat.c \
    src/dispatch/fhsm_dispatch_hybrid.c \
    src/dispatch/fhsm_dispatch_composite.c \
    kat/fhsm_kat_vectors.c              \
    kat/cavp_extended.c

# Dispatch source files need the dispatch common header on their include path.
CFLAGS += -Isrc/dispatch

# Optional object-store cap override (default 64, see src/fhsm_token.c).
# The pkcs11-check target builds with a larger store : the harness
# creates many objects over a full run and does not destroy the session
# objects it creates, so the default store would fill and cascade
# CKR_DEVICE_MEMORY across unrelated later tests. See FINDINGS I1 / F5.
ifdef FHSM_MAX_OBJECTS
CFLAGS += -DFHSM_MAX_OBJECTS=$(FHSM_MAX_OBJECTS)
endif

# Objects are built out of tree. This repository is normally checked out on a
# VirtualBox shared folder, where vboxsf is slow on the many small writes a C
# build produces and serves mtimes from the host clock while make compares
# them against the guest's. Sources stay where they are -- they are read, not
# rewritten -- and the objects go wherever OBJDIR points, which on that setup
# is a native filesystem.
#
# The default is in-tree so that a fresh clone behaves the way a contributor
# expects. Override it in the environment:  export OBJDIR=$HOME/.cache/freehsm
OBJDIR ?= .obj
LIB_OBJ = $(patsubst %.c,$(OBJDIR)/%.o,$(LIB_SRC))

LIB     = libfreehsm-fips.so
LIB_VER = $(LIB).$(shell awk -F'"' '/FHSM_VERSION_STRING/{print $$2; exit}' include/fhsm_common.h)

# ---------------------------------------------------------------------------
# Default target
# ---------------------------------------------------------------------------
# The four PKI tools link only src/fhsm_composite.o, not the module, so a
# change to that file can compile inside the module and fail to link outside
# it. That is exactly what happened: `all` did not name these binaries, the
# release pre-flight ran `all`, and a tree in which a quarter of the shipped
# programs did not build was validated and tagged. They are named here so the
# question cannot be asked again.
TOOLS = tools/fhsm-csr tools/fhsm-ca tools/fhsm-sign tools/fhsm-token

.PHONY: audit-switch all
all: generate $(LIB) tests/test_smoke tools/freehsm-audit $(TOOLS)

# Built against the same OpenSSL as everything else. This rule used to be a
# bare `cc ... -lcrypto`, the only one in the file ignoring OPENSSL_PREFIX. It
# builds anyway wherever the system headers happen to be on the default path,
# which is why nobody noticed -- and where they are not, the release pre-flight
# fails at the last tool. Worse where it does build: the audit tool would link
# a different libcrypto from the module it audits, which is precisely the sort
# of divergence an audit tool exists to rule out.
tools/freehsm-audit: tools/freehsm_audit.c
	$(CC) -O2 -Wall -Wextra $(OPENSSL_CFLAGS) -o $@ $< $(OPENSSL_LDFLAGS)

# fhsm-csr links only the composite encoder -- src/fhsm_composite.o stands
# alone against libcrypto -- and loads the PKCS#11 module at runtime through
# C_GetFunctionList, the one symbol the standard requires.
#
# This comment used to claim the tool "drives any module implementing the
# mechanism". It did not: load_module dlsym'd each C_* by name and exited if
# one was missing, so it drove modules that export all of them -- ours -- and
# nothing else. p11-kit-client.so exports exactly one symbol, and the tool
# answered "C_Initialize missing from module".
#
# One limitation remains, and is not fixed here: --slot takes a raw
# CK_SLOT_ID and defaults to 0. A module whose slot IDs are not small
# integers cannot be addressed at all, because the tools never call
# C_GetSlotList. See docs/ROADMAP.md.
tools/fhsm-csr: tools/fhsm_csr.c tools/p11_util.h $(OBJDIR)/src/fhsm_composite.o
	$(CC) $(CFLAGS) -Itools -o $@ $< $(OBJDIR)/src/fhsm_composite.o $(LDFLAGS) -ldl

# fhsm-ca signs for other people; fhsm-csr makes requests and its own root.
# Separate binaries because they are separate authorities, usually separate
# operators, and a single tool named for one of them would misname the other.
tools/fhsm-ca: tools/fhsm_ca.c tools/p11_util.h $(OBJDIR)/src/fhsm_composite.o
	$(CC) $(CFLAGS) -Itools -o $@ $< $(OBJDIR)/src/fhsm_composite.o $(LDFLAGS) -ldl

tools/fhsm-sign: tools/fhsm_sign.c tools/p11_util.h $(OBJDIR)/src/fhsm_composite.o
	$(CC) $(CFLAGS) -Itools -o $@ $< $(OBJDIR)/src/fhsm_composite.o $(LDFLAGS) -ldl

tools/fhsm-token: tools/fhsm_token.c tools/p11_util.h $(OBJDIR)/src/fhsm_composite.o
	$(CC) $(CFLAGS) -Itools -o $@ $< $(OBJDIR)/src/fhsm_composite.o $(LDFLAGS) -ldl

# ---------------------------------------------------------------------------
# Code generation --- runs scripts/gen_p11_thunks.py to regenerate
# include/fhsm_pkcs11_mechanisms.h, src/gen/fhsm_dispatch.c, docs/MECHANISMS.md.
# The profile defaults to fips-strict; override with PROFILE=interop.
# ---------------------------------------------------------------------------
PROFILE ?= fips-strict

# Witness file recording the profile the generated sources were produced with.
#
# Without this, `make PROFILE=interop` silently did nothing: the generated
# artifacts depended only on gen_p11_thunks.py, so an existing set built for
# another profile satisfied the rule and the build linked the wrong dispatch
# table. The failure is silent in the dangerous direction too -- a tree last
# generated for interop, rebuilt without PROFILE, ships the non-FIPS mechanisms
# enabled while every visible sign says fips-strict. Getting the profile right
# should not depend on remembering to run `make generate` first.
#
# .profile.stamp is rewritten only when the profile actually changes, so it does
# not force a rebuild on every invocation.
PROFILE_STAMP := src/gen/.profile.stamp

.PHONY: profile-stamp
profile-stamp:
	@mkdir -p $(dir $(PROFILE_STAMP))
	@if [ "$$(cat $(PROFILE_STAMP) 2>/dev/null)" != "$(PROFILE)" ]; then \
	    printf '%s' '$(PROFILE)' > $(PROFILE_STAMP); \
	    echo "[freehsm] profile -> $(PROFILE) (regenerating)"; \
	fi

$(PROFILE_STAMP): profile-stamp
	@:

# The stamp watches a transition; this watches the state.
#
# The stamp is rewritten when PROFILE changes, which covers the operator who
# forgets the flag. It does not cover the generated files changing underneath
# it -- a git checkout, a branch switch, a merge, a stash pop. When that
# happens the stamp still says one profile while src/gen says the other, make
# sees nothing out of date, and the build links a dispatch table nobody asked
# for. Found the hard way: restoring src/gen from HEAD left a fips-strict
# dispatch behind an interop stamp, and the only symptom was CKR_MECHANISM_
# INVALID from a mechanism that was supposed to be enabled.
#
# The dangerous direction is the other one. A tree generated for interop and
# rebuilt as fips-strict ships the non-approved mechanisms live while every
# visible sign says otherwise, and nothing downstream would catch it --
# docs/ROADMAP.md already names this as the check that cannot be recovered
# after a release.
#
# So: assert the post-condition. fhsm_build_fips_strict is written by the
# generator and read by the profile gates, which makes it the one value that
# cannot be right by accident.
.PHONY: check-profile
check-profile:
	@want=$$( [ "$(PROFILE)" = "interop" ] && echo 0 || echo 1 ); 	got=$$(sed -n 's/^const int fhsm_build_fips_strict = \([01]\);.*/\1/p' \
	        src/gen/fhsm_dispatch.c 2>/dev/null); 	if [ -z "$$got" ]; then 	    echo "[freehsm] cannot read fhsm_build_fips_strict from src/gen/fhsm_dispatch.c" >&2; 	    exit 1; 	fi; 	if [ "$$got" != "$$want" ]; then 	    echo "[freehsm] PROFILE=$(PROFILE) but the generated dispatch says" >&2; 	    echo "          fhsm_build_fips_strict = $$got (expected $$want)." >&2; 	    echo "          The generated sources and the profile stamp disagree --" >&2; 	    echo "          usually a checkout or merge replaced src/gen underneath." >&2; 	    echo "          Run:  rm -f $(PROFILE_STAMP) && make PROFILE=$(PROFILE) generate" >&2; 	    exit 1; 	fi

.PHONY: generate
generate:
	python3 scripts/gen_p11_thunks.py --profile=$(PROFILE)

# Generated artifacts depend on the script (so editing it triggers a re-gen)
# AND on the profile witness (so switching profiles does too).
include/fhsm_pkcs11_mechanisms.h src/gen/fhsm_dispatch.c docs/MECHANISMS.md: scripts/gen_p11_thunks.py $(PROFILE_STAMP)
	$(MAKE) generate

# Report the profile the current generated sources were built for. Cheap way to
# answer "what am I actually running?" without reading fhsm_dispatch.c.
.PHONY: show-profile
show-profile:
	@echo "PROFILE (requested) : $(PROFILE)"
	@echo "generated sources   : $$(cat $(PROFILE_STAMP) 2>/dev/null || echo '<jamais genere>')"
	@echo -n "fhsm_build_fips_strict = "
	@grep -oE 'fhsm_build_fips_strict = [01]' src/gen/fhsm_dispatch.c 2>/dev/null \
	    | grep -oE '[01]$$' || echo '?'

# The choke point: everything that carries the profile goes through this
# object, so gating it covers the library, the tests and the tools alike --
# gating only $(LIB) would leave `make tests` building against a dispatch the
# check never looked at.
$(OBJDIR)/src/gen/fhsm_dispatch.o: | check-profile

$(LIB): $(LIB_OBJ) | check-profile
	$(CC) -shared -Wl,-soname,$(LIB) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c -o $@ $<

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
# test_smoke is an INTERNAL test : it accesses helpers (fhsm_state_get,
# fhsm_rng_bytes, fhsm_aes_gcm_*, fhsm_ct_memcmp, fhsm_kat_results) that
# are hidden in the shipped .so (visibility=hidden). For testing we link
# against the .o files directly, which bypasses visibility filtering.
# Integrity self-check regression (#125). INTERNAL linking model: the test
# binary embeds its own .fhsm_digest section (from fhsm_integrity.o), so it
# can be signed by scripts/sign_module.sh exactly like the shipped .so.
#
# This is the only place the integrity check is exercised WITHOUT
# FHSM_INTEGRITY_ALLOW_UNSIGNED. That matters: the check shipped inert twice
# (an unconditional pass until v1.2.1, then an always-fail caused by a missing
# `volatile` on the digest slot), and neither was caught because every other
# caller sets the bypass. `unset` below is deliberate -- the test refuses to
# run if the variable leaks in from the environment.
tests/test_integrity: tests/test_integrity.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

.PHONY: test-integrity
test-integrity: tests/test_integrity
	@echo "test_integrity : module integrity self-check (no bypass)"
	@# 1. Fresh build: digest slot is all zeros -> must NOT verify.
	@env -u FHSM_INTEGRITY_ALLOW_UNSIGNED ./tests/test_integrity unsigned
	@# 2. Sign it, exactly as the shipped module is signed.
	@bash scripts/sign_module.sh ./tests/test_integrity >/dev/null
	@env -u FHSM_INTEGRITY_ALLOW_UNSIGNED ./tests/test_integrity signed
	@# 3. Flip one byte of the signed image (in a copy) -> must NOT verify.
	@cp ./tests/test_integrity ./tests/test_integrity.tampered
	@python3 -c "import sys; \
p='./tests/test_integrity.tampered'; d=bytearray(open(p,'rb').read()); \
off=d.find(b'FHSM_TAMPER_CANARY'); \
d[off+18]^=0x01; open(p,'wb').write(d)"
	@chmod +x ./tests/test_integrity.tampered
	@env -u FHSM_INTEGRITY_ALLOW_UNSIGNED ./tests/test_integrity.tampered tampered
	@rm -f ./tests/test_integrity.tampered
	@echo "test_integrity : PASS"

# Config reader (#128) : proves the two shipped keys are actually read, that
# bad values fall back to the documented default, and that key matching is
# exact. Links the objects because the reader is internal, not exported.
# Sensitive values in the mlock'd arena (#127) : proves the routing, that
# non-sensitive values stay out, and that exhaustion fails rather than
# silently falling back to pageable memory.
# Capacity micro-benchmark (not a test) : cost of creating N objects and of a
# worst-case lookup, to answer "can FHSM_MAX_OBJECTS grow" with numbers.
# Concurrent PKCS#11 use (#111-prep). Links the shared object with -ldl so it
# exercises the module exactly as a caller would. Meant to be run under
# `make TSAN=1`; it is written to be able to fail.
tests/test_concurrency: tests/test_concurrency.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl -lpthread

tests/bench_capacity: tests/bench_capacity.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

# Not part of `make tests`: a measurement, not an assertion. See the file.
tests/bench_audit_rate: tests/bench_audit_rate.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_secure_heap: tests/test_secure_heap.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_conf: tests/test_conf.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

# CKM_AES_CBC_PAD decrypt behaviour (R2). Links the shared object with -ldl so
# it drives the module exactly as a caller would, like tests/test_concurrency.
tests/test_cbc_pad_oracle: tests/test_cbc_pad_oracle.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

# Composite ML-DSA combiner against the draft's Appendix D vectors (#112).
tests/test_composite_mprime: tests/test_composite_mprime.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_composite_sign: tests/test_composite_sign.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

# Composite ML-DSA through the PKCS#11 surface (#112). Links the shared object
# with -ldl so it drives the module exactly as a caller would, and so the
# profile baked into the .so is what the test observes.
tests/test_composite_p11: tests/test_composite_p11.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

tests/test_composite_x509: tests/test_composite_x509.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_composite_csr: tests/test_composite_csr.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_composite_issue: tests/test_composite_issue.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_composite_crl: tests/test_composite_crl.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_composite_prehash: tests/test_composite_prehash.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_composite_cms: tests/test_composite_cms.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_composite_ocsp: tests/test_composite_ocsp.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_pin_length: tests/test_pin_length.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_throttle_reboot: tests/test_throttle_reboot.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_audit_fsync: tests/test_audit_fsync.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS) -lpthread

tests/test_audit_concurrent: tests/test_audit_concurrent.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS) -lpthread

tests/test_audit_multiproc: tests/test_audit_multiproc.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS) -lpthread

tests/test_audit_switch: tests/test_audit_switch.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS) -lpthread

tests/test_audit_key: tests/test_audit_key.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_audit_backpressure: tests/test_audit_backpressure.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

tests/test_audit_verify: tests/test_audit_verify.c $(LIB_OBJ) tools/freehsm-audit
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

# -Itools: this test exercises the tools' real loader rather than a copy of it.
tests/test_p11_loader: tests/test_p11_loader.c $(LIB)
	$(CC) $(CFLAGS) -Itools -o $@ $< $(LDFLAGS) -ldl

# Single-action driver for the real-TPM validation (#109). NOT part of `make
# tests`: it needs a TPM, a provisioned parent handle, and a reboot between
# phases -- see scripts/validate_tpm_sealing.sh.
tests/tpm_hw_probe: tests/tpm_hw_probe.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

# TPM 2.0 sealing (#109). fhsm_tpm.c is recompiled here with
# -DFHSM_TPM_TEST_HOOKS, which is what lets FHSM_TPM_DEVICE / FHSM_TPM_CMD
# redirect the module at tests/tpm2-stub.sh. That macro is set by this rule
# and by nothing else: the shipped library has no way to be pointed at a fake
# TPM, which is the whole reason the seam is compile-time and not an
# environment variable the module always reads.
$(OBJDIR)/tests/fhsm_tpm_testhooks.o: src/fhsm_tpm.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -DFHSM_TPM_TEST_HOOKS -c -o $@ $<

tests/test_tpm: tests/test_tpm.c $(OBJDIR)/tests/fhsm_tpm_testhooks.o $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(OBJDIR)/tests/fhsm_tpm_testhooks.o \
	    $(filter-out $(OBJDIR)/src/fhsm_tpm.o,$(LIB_OBJ)) $(LDFLAGS) -lpthread

tests/test_smoke: tests/test_smoke.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

# Regression test for the objects-blob loader bound (#108) and the v2
# variable-record blob (#110) : >11-object and certificate-sized
# round-trips must survive close + reload. Same INTERNAL linking model
# as test_smoke.
tests/test_token_capacity: tests/test_token_capacity.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)

# Test binaries are statically linked against the .o files : their
# .fhsm_digest section keeps the zero placeholder (only the shipped .so
# is patched by `make integrity`). FHSM_INTEGRITY_ALLOW_UNSIGNED=1 is
# therefore required here, same convention as tests/coverage_matrix.sh.
# NULL-argument robustness regression (#125 pkcs11-check finding) :
# drives the PUBLIC API via dlopen, so it links against the built .so
# rather than the .o files. Requires $(LIB) to exist.
tests/test_decrypt_null_args: tests/test_decrypt_null_args.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

# TSFI robustness guards (#125) : NULL template / data pointers and
# integer-overflow counts must return CKR_ARGUMENTS_BAD, not SIGSEGV.
tests/test_robustness_args: tests/test_robustness_args.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

# Per-session operation-state hygiene (#125) : session-handle reuse must
# not bleed CKR_OPERATION_ACTIVE ; C_Sign undersized buffer must return
# CKR_BUFFER_TOO_SMALL and preserve the operation.
tests/test_op_state: tests/test_op_state.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

# FIPS-approved digest/HMAC mechanisms advertised but previously not
# callable (#125) : SHA-224, SHA-512/t, SHA-3, and their HMACs.
tests/test_fips_digests: tests/test_fips_digests.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

# C_GetAttributeValue boolean/date attribute coverage (#125).
tests/test_attributes: tests/test_attributes.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

# Parameter / attribute validation hardening (#125).
tests/test_input_validation: tests/test_input_validation.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

# PKCS#11 CKA_TOKEN semantics : session objects destroyed on close (#125).
tests/test_session_objects: tests/test_session_objects.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

# Mechanism advertisement coherence guard (#125) : C_GetMechanismList /
# C_GetMechanismInfo derived from the generated dispatch table must stay
# consistent (correct PQ values, EdDSA/HKDF present, no phantoms).
tests/test_mech_advertise: tests/test_mech_advertise.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

# Non-FIPS digest gating (#125 general-purpose) : SHA-1/MD5 executable
# in interop, rejected in fips-strict. Profile-adaptive.
tests/test_legacy_digest: tests/test_legacy_digest.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

# Non-FIPS cipher gating (#125) : AES-ECB (+3DES) executable in interop,
# rejected in fips-strict. Profile-adaptive round-trip.
tests/test_legacy_cipher: tests/test_legacy_cipher.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

# Non-FIPS RSA legacy padding gating (#125) : RSA-PKCS v1.5 / X.509 raw.
tests/test_legacy_rsa: tests/test_legacy_rsa.c $(LIB)
	$(CC) $(CFLAGS) -o $@ $< -ldl

.PHONY: tests
# Every test gets its own tokens directory. It used to be only the ones that
# touch a token -- but C_Initialize now opens the audit log, which lives
# beside the tokens, so any test that initialises the module writes there.
# Without this they all fall back to /var/lib/freehsm/tokens and fail with a
# bare 0x6 on any machine where that does not exist.
tests: tests/test_tpm tests/test_cbc_pad_oracle tests/test_composite_mprime tests/test_composite_sign tests/test_composite_p11 tests/test_composite_x509 tests/test_composite_csr tests/test_composite_issue tests/test_composite_crl tests/test_composite_prehash tests/test_composite_cms tests/test_composite_ocsp tests/test_pin_length tests/test_throttle_reboot tests/test_audit_fsync tests/test_audit_concurrent tests/test_audit_multiproc tests/test_audit_switch tests/test_audit_key tests/test_audit_backpressure tests/test_audit_verify tests/test_p11_loader tests/test_smoke tests/test_token_capacity tests/test_decrypt_null_args tests/test_mech_advertise tests/test_legacy_digest tests/test_legacy_cipher tests/test_legacy_rsa tests/test_robustness_args tests/test_op_state tests/test_fips_digests tests/test_attributes tests/test_input_validation tests/test_session_objects tools/fhsm-token
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_smoke
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_tpm
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) OPENSSL_CONF=/dev/null \
		LD_LIBRARY_PATH=. ./tests/test_cbc_pad_oracle
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_composite_mprime
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_composite_sign
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) \
		LD_LIBRARY_PATH=. ./tests/test_composite_p11
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_composite_x509
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_composite_csr
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_composite_issue
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_composite_crl
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_composite_prehash
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_composite_cms
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_composite_ocsp
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_audit_key
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_audit_backpressure
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_pin_length
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_throttle_reboot
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_audit_fsync
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_audit_concurrent
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_audit_multiproc
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_audit_switch
	LD_LIBRARY_PATH=. sh tests/audit_switch.sh mandatory
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_audit_verify
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_p11_loader ./libfreehsm-fips.so
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) LD_LIBRARY_PATH=. ./tests/test_token_capacity
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) OPENSSL_CONF=/dev/null \
		LD_LIBRARY_PATH=. ./tests/test_decrypt_null_args
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) OPENSSL_CONF=/dev/null \
		LD_LIBRARY_PATH=. ./tests/test_robustness_args
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) OPENSSL_CONF=/dev/null \
		LD_LIBRARY_PATH=. ./tests/test_op_state
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) OPENSSL_CONF=/dev/null \
		LD_LIBRARY_PATH=. ./tests/test_fips_digests
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) OPENSSL_CONF=/dev/null \
		LD_LIBRARY_PATH=. ./tests/test_attributes
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) OPENSSL_CONF=/dev/null \
		LD_LIBRARY_PATH=. ./tests/test_input_validation
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) OPENSSL_CONF=/dev/null \
		LD_LIBRARY_PATH=. ./tests/test_session_objects
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) OPENSSL_CONF=/dev/null \
		LD_LIBRARY_PATH=. ./tests/test_mech_advertise
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) OPENSSL_CONF=/dev/null \
		LD_LIBRARY_PATH=. ./tests/test_legacy_digest
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) OPENSSL_CONF=/dev/null \
		LD_LIBRARY_PATH=. ./tests/test_legacy_cipher
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$$(mktemp -d) OPENSSL_CONF=/dev/null \
		LD_LIBRARY_PATH=. ./tests/test_legacy_rsa

# External behavioral harness (#125) : Denis Mingulov's pkcs11-check
# (>100k vendor-neutral checks) against the built module. Findings are
# evidence, not a gate --- see scripts/run_pkcs11_check.sh. Requires
# opensc (pkcs11-tool) and `pip install pkcs11-check` (Python >= 3.12).
# Run against an UNSIGNED dev build ; CI runs the signed module.
.PHONY: pkcs11-check
pkcs11-check:
	# Built at the default FHSM_MAX_OBJECTS. The 4096 override that used to
	# be here was a workaround from when the default was 64: the harness's
	# object churn filled the store and masked findings behind
	# CKR_DEVICE_MEMORY (FINDINGS I1 / F5). The deeper fix that comment
	# asked for -- destroying session objects on C_CloseSession -- landed in
	# #125, and the default is now 1024.
	$(MAKE) clean
	$(MAKE)
	$(MAKE) integrity
	FHSM_ALLOW_UNSIGNED=1 bash scripts/run_pkcs11_check.sh ./$(LIB) ./reports/pkcs11-check

# ---------------------------------------------------------------------------
# Integrity --- sign the shipped .so and embed its SHA-256 into the
# fhsm_module_integrity_digest[] array. Done by scripts/sign_module.sh
# as a two-pass build (zero placeholder -> real digest patched in).
# Required by FIPS 140-3 §7.10.2 (pre-operational integrity self-test).
# ---------------------------------------------------------------------------
.PHONY: integrity
# The audit switch has two sides and `make tests` only exercises one: the
# default build refuses FHSM_AUDIT=off, so the branch that honours it is never
# reached. This runs both, and is the reason EXTRA_CFLAGS exists.
audit-switch:
	$(MAKE) clean
	$(MAKE) all tests/test_audit_switch
	LD_LIBRARY_PATH=. sh tests/audit_switch.sh mandatory
	$(MAKE) clean
	$(MAKE) EXTRA_CFLAGS=-DFHSM_AUDIT_MANDATORY=0 all tests/test_audit_switch
	LD_LIBRARY_PATH=. sh tests/audit_switch.sh optional
	@echo "[audit-switch] both sides of FHSM_AUDIT_MANDATORY exercised"

integrity: $(LIB)
	@scripts/sign_module.sh $(LIB)
	@echo "[integrity] $(LIB) signed ; readback :"
	@objcopy --dump-section .fhsm_digest=/dev/stdout $(LIB) /dev/null \
	    2>/dev/null | xxd -p | tr -d '\n' ; echo

# Strip-and-sign : produce a release artefact with debug info removed
# and the digest patched. Goes hand-in-hand with `make repro`.
.PHONY: release
release: $(LIB)
	@objcopy --strip-debug $(LIB)
	@scripts/sign_module.sh $(LIB)

# ---------------------------------------------------------------------------
# Lint --- the build refuses to ship if cppcheck or scan-build flags any
# defect. Both are part of the CC EAL4+ ALC_TAT.1 ("well-defined
# development tools") evidence package.
# ---------------------------------------------------------------------------
.PHONY: lint
lint:
	cppcheck --enable=warning,style,performance,portability \
	         --error-exitcode=1 --std=c11 --inline-suppr \
	         -Iinclude src/ kat/

# ---------------------------------------------------------------------------
# Clean
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Install --- system-wide installation under PREFIX (defaults to /opt/freehsm).
# Run as root (or with sudo). The procedure follows docs/AGD_PRE.md §3.
# ---------------------------------------------------------------------------
PREFIX     ?= /opt/freehsm
LIBDIR     ?= $(PREFIX)/lib
# The module reads /etc/freehsm/freehsm.conf (FHSM_CONF_PATH_DEFAULT in
# src/fhsm_conf.c), not $(PREFIX)/etc. Installing under PREFIX put the file
# somewhere nothing would ever open it -- a configuration that cannot take
# effect, which is the same defect #128 removed from the file's contents.
# Override FHSM_CONFDIR only if you also change FHSM_CONF_PATH_DEFAULT.
FHSM_CONFDIR ?= /etc/freehsm
ETCDIR     ?= $(FHSM_CONFDIR)
STATEDIR   ?= /var/lib/freehsm
SYSUSER    ?= freehsm

.PHONY: install
install: $(LIB)
	@echo "[install] target prefix = $(PREFIX)"
	install -d -o root -g root -m 755 $(LIBDIR) $(ETCDIR)
	install -o root -g root -m 0755 $(LIB) $(LIBDIR)/$(LIB)
	id -u $(SYSUSER) >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d $(STATEDIR) $(SYSUSER)
	install -d -o $(SYSUSER) -g $(SYSUSER) -m 700 $(STATEDIR)/tokens $(STATEDIR)/audit $(STATEDIR)/kek
	test -f $(ETCDIR)/freehsm.conf || printf '# freehsm.conf --- runtime configuration.\n#\n# Every key below is read by the module. Nothing else is: the rest of the\n# module is configured at compile time (FHSM_PIN_MAX_FAILED, the PBKDF2\n# iteration count, the throttle curve) or through the environment\n# (FHSM_TOKENS_DIR, FHSM_MODE). Until v1.6.0 this file listed nine keys and\n# no code read any of them -- a file that promises controls nothing enforces.\n\n# Runtime mode: fips | legacy. Overridden by the FHSM_MODE environment\n# variable. NOTE its narrow scope: this selects the KAT/dispatch behaviour\n# only. Which mechanisms the PKCS#11 API advertises and executes is fixed\n# when the module is built (make generate PROFILE=fips-strict|interop) and\n# cannot be changed here.\nmode = legacy\n\n# Size of the mlock(2)-ed secure heap holding key material, in KiB.\n# Range 64..65536, rounded UP to a power of two (the arena allocator requires\n# one). Out-of-range or unparseable values fall back to the compiled default.\n# Raise this if the module reports CKR_DEVICE_MEMORY when loading a token with\n# many private keys.\nsecure_heap_kb = 8192\n' > $(ETCDIR)/freehsm.conf
	chmod 0644 $(ETCDIR)/freehsm.conf
	-setcap 'cap_ipc_lock=+ep' $(LIBDIR)/$(LIB)
	install -d -o root -g root -m 755 $(PREFIX)/share/kat
	install -o root -g root -m 0644 kat/cavp/*.rsp $(PREFIX)/share/kat/ 2>/dev/null || true
	install -d -o root -g root -m 755 $(PREFIX)/bin
	test -f tools/freehsm-audit && install -o root -g root -m 0755 tools/freehsm-audit $(PREFIX)/bin/freehsm-audit || true
	@echo "[install] installed to $(LIBDIR)/$(LIB)"
	@echo "[install] verify with : readelf -p .comment $(LIBDIR)/$(LIB)"

.PHONY: uninstall
uninstall:
	@echo "[uninstall] WARNING : this WILL DESTROY all tokens, audit logs and KEK."
	@echo "[uninstall] Press Ctrl-C now to abort, or wait 5 s..."
	@sleep 5
	-systemctl stop freehsm-bound-service 2>/dev/null || true
	-shred -uvz $(STATEDIR)/tokens/*.tok 2>/dev/null || true
	-shred -uvz $(STATEDIR)/audit/*.audit.log 2>/dev/null || true
	-shred -uvz $(STATEDIR)/kek/*.kek 2>/dev/null || true
	rm -f $(LIBDIR)/$(LIB) $(ETCDIR)/freehsm.conf
	rm -rf $(STATEDIR)
	-userdel $(SYSUSER) 2>/dev/null || true
	@echo "[uninstall] done."

.PHONY: clean
clean:
	rm -rf $(OBJDIR)
	rm -f $(LIB) tests/test_smoke tests/*.o
	rm -f tools/freehsm-audit $(TOOLS)
	rm -f freehsm-c-src.tar.xz freehsm-c-src.tar.xz.sha256
	rm -rf out/

# Distclean = clean + regenerable artefacts. Use before `make dist` to
# guarantee everything is regenerated from scratch.
.PHONY: distclean
distclean: clean
	rm -f include/fhsm_pkcs11_mechanisms.h
	rm -f src/gen/fhsm_dispatch.c
	rm -f docs/MECHANISMS.md
	rm -rf __pycache__ scripts/__pycache__

# ---------------------------------------------------------------------------
# Source distribution (reproducible). Input to CC EAL4+ ALC_CMS.4.
# Honors SOURCE_DATE_EPOCH and uses tar's deterministic flags so the
# archive is bit-identical across hosts.
# ---------------------------------------------------------------------------
SOURCE_DATE_EPOCH ?= 1735689600
SOURCE_DATE_STR   := $(shell date -u -d @$(SOURCE_DATE_EPOCH) '+%Y-%m-%d %H:%M:%S')

.PHONY: dist
dist: clean
	@echo "[dist] mtime = $(SOURCE_DATE_STR) UTC"
	tar --mtime="@$(SOURCE_DATE_EPOCH)" \
	    --owner=root --group=root --numeric-owner \
	    --sort=name --no-acls --no-xattrs \
	    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime,delete=mtime \
	    --transform 's,^,freehsm-c-$(FHSM_VERSION_STRING)/,' \
	    -cJf freehsm-c-src.tar.xz \
	    Makefile Dockerfile.build \
	    include/ src/ kat/ tests/ docs/ scripts/
	@sha256sum freehsm-c-src.tar.xz | tee freehsm-c-src.tar.xz.sha256
	@echo "[dist] freehsm-c-src.tar.xz ready --- distribute to the evaluation lab."

# ---------------------------------------------------------------------------
# Reproducible build via Docker.
# ---------------------------------------------------------------------------
.PHONY: repro
repro:
	@scripts/build_reproducible.sh

.PHONY: dist-verify
dist-verify:
	@# If a release reference digest exists for this version, compare
	@# against it. Otherwise fall back to the build-twice consistency
	@# check (no signed reference yet -- useful during development).
	@# FHSM_VERSION_STRING comes from the variable at the top of this file,
	@# which parses the header with awk. The grep -oP that used to be here
	@# looked for `FHSM_VERSION_STRING = "..."` and the header writes
	@# `#define FHSM_VERSION_STRING  "..."`, so it never matched and this
	@# recipe compared against dist/refs/v.sha256 -- a file that cannot exist.
	@VERSION='$(FHSM_VERSION_STRING)'; \
	if [ -f dist/refs/v$$VERSION.sha256 ]; then \
	    echo "[dist-verify] reference found for v$$VERSION ; comparing local build"; \
	    scripts/dist_verify_ref.sh; \
	else \
	    echo "[dist-verify] no reference at dist/refs/v$$VERSION.sha256"; \
	    echo "[dist-verify] falling back to build-twice consistency check"; \
	    scripts/verify_reproducibility.sh; \
	fi

.PHONY: dist-baseline
dist-baseline:
	@scripts/dist_baseline.sh

.PHONY: repro-shell
repro-shell:
	@scripts/build_reproducible.sh --shell
