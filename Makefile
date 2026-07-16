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

CFLAGS  = $(WARN_FLAGS) $(HARDEN_FLAGS) $(REPRO_FLAGS) $(DEBUG_FLAGS) \
          -std=c11 -D_GNU_SOURCE \
          -Iinclude $(OPENSSL_CFLAGS)

# Linker reproducibility :
#   --build-id=none        suppress the random .note.gnu.build-id slot
#   --hash-style=gnu       deterministic hash table layout
#   --sort-common          stable .bss/.common ordering
#   --reproducible         ld >= 2.38 honors the bundle (binutils 2.38+)
LDFLAGS = -Wl,-z,relro,-z,now,-z,noexecstack,-z,defs \
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
    src/fhsm_drbg.c                   \
    src/fhsm_tpm.c                    \
    src/fhsm_token_tpm.c              \
    src/fhsm_mode.c                   \
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

LIB_OBJ = $(LIB_SRC:.c=.o)

LIB     = libfreehsm-fips.so
LIB_VER = $(LIB).$(shell awk -F'"' '/FHSM_VERSION_STRING/{print $$2; exit}' include/fhsm_common.h)

# ---------------------------------------------------------------------------
# Default target
# ---------------------------------------------------------------------------
.PHONY: all
all: generate $(LIB) tests/test_smoke tools/freehsm-audit

tools/freehsm-audit: tools/freehsm_audit.c
	cc -O2 -Wall -Wextra -o $@ $< -lcrypto

# ---------------------------------------------------------------------------
# Code generation --- runs scripts/gen_p11_thunks.py to regenerate
# include/fhsm_pkcs11_mechanisms.h, src/gen/fhsm_dispatch.c, docs/MECHANISMS.md.
# The profile defaults to fips-strict; override with PROFILE=interop.
# ---------------------------------------------------------------------------
PROFILE ?= fips-strict

.PHONY: generate
generate:
	python3 scripts/gen_p11_thunks.py --profile=$(PROFILE)

# Generated artifacts depend on the script (so editing it triggers a re-gen).
include/fhsm_pkcs11_mechanisms.h src/gen/fhsm_dispatch.c docs/MECHANISMS.md: scripts/gen_p11_thunks.py
	$(MAKE) generate

$(LIB): $(LIB_OBJ)
	$(CC) -shared -Wl,-soname,$(LIB) -o $@ $^ $(LDFLAGS)

%.o: %.c
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
tests: tests/test_smoke tests/test_token_capacity tests/test_decrypt_null_args tests/test_mech_advertise tests/test_legacy_digest tests/test_legacy_cipher tests/test_legacy_rsa tests/test_robustness_args tests/test_op_state tests/test_fips_digests tests/test_attributes tests/test_input_validation tests/test_session_objects
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 LD_LIBRARY_PATH=. ./tests/test_smoke
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 LD_LIBRARY_PATH=. ./tests/test_token_capacity
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
	FHSM_INTEGRITY_ALLOW_UNSIGNED=1 OPENSSL_CONF=/dev/null \
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
	# Rebuild the module under test with a large object store so the
	# harness's object churn does not fill the default 64-slot token and
	# mask real findings behind CKR_DEVICE_MEMORY (FINDINGS I1 / F5). The
	# deeper fix is destroying session objects on C_CloseSession.
	$(MAKE) clean
	$(MAKE) FHSM_MAX_OBJECTS=4096
	$(MAKE) FHSM_MAX_OBJECTS=4096 integrity
	FHSM_ALLOW_UNSIGNED=1 bash scripts/run_pkcs11_check.sh ./$(LIB) ./reports/pkcs11-check

# ---------------------------------------------------------------------------
# Integrity --- sign the shipped .so and embed its SHA-256 into the
# fhsm_module_integrity_digest[] array. Done by scripts/sign_module.sh
# as a two-pass build (zero placeholder -> real digest patched in).
# Required by FIPS 140-3 §7.10.2 (pre-operational integrity self-test).
# ---------------------------------------------------------------------------
.PHONY: integrity
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
ETCDIR     ?= $(PREFIX)/etc
STATEDIR   ?= /var/lib/freehsm
SYSUSER    ?= freehsm

.PHONY: install
install: $(LIB)
	@echo "[install] target prefix = $(PREFIX)"
	install -d -o root -g root -m 755 $(LIBDIR) $(ETCDIR)
	install -o root -g root -m 0755 $(LIB) $(LIBDIR)/$(LIB)
	id -u $(SYSUSER) >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin -d $(STATEDIR) $(SYSUSER)
	install -d -o $(SYSUSER) -g $(SYSUSER) -m 700 $(STATEDIR)/tokens $(STATEDIR)/audit $(STATEDIR)/kek
	test -f $(ETCDIR)/freehsm.conf || printf '[module]\nfips_strict      = true\naudit_mandatory  = true\nsecure_heap_kb   = 256\n\n[token]\npin_max_failed         = 5\npin_throttle_base_ms   = 500\npin_throttle_max_ms    = 60000\npbkdf2_iterations      = 200000\n\n[paths]\ntokens_dir = $(STATEDIR)/tokens\naudit_dir  = $(STATEDIR)/audit\n' > $(ETCDIR)/freehsm.conf
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
	rm -f $(LIB) $(LIB_OBJ) tests/test_smoke tests/*.o
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
	@VERSION=$$(grep -oP 'FHSM_VERSION_STRING\s*=\s*"\K[^"]+' include/fhsm_common.h 2>/dev/null); \
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
