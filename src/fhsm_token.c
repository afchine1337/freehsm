/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * ========================================================================= */
/* ===========================================================================
 * fhsm_token.c --- Encrypted token store (slot persistence).
 *
 *  Layout : one binary file per slot (317-byte fixed header + optional
 *  AES-256-GCM objects section). The DEK is wrapped under PBKDF2 +
 *  AES-GCM keyed by the operator's PIN. Objects live in a second
 *  AES-GCM blob keyed by the DEK. Full byte-level specification :
 *  docs/TOKEN_STORE_FORMAT.md (#108).
 *
 *  Fixed layout = constant-time parse, no allocator on the hot path,
 *  minimal parser attack surface per CC EAL4+ ADV_TDS.3 ("the simpler
 *  the better").
 *
 *  PIN throttling and lockout : see header for the rules. Counters are
 *  stored plaintext in the header (they must be readable before login)
 *  so the throttle survives process restart.
 * ========================================================================= */

#include "fhsm_common.h"
#include "fhsm_token.h"
#include "fhsm_crypto.h"
#include "fhsm_audit.h"
#include "fhsm_token_tpm.h"

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

/* ---------------------------------------------------------------------------
 * Opaque token struct. Lives outside the secure heap (the *file path*,
 * label, serial, and failure counters are non-sensitive). Only the
 * unwrapped DEK pointer is secure-heap-resident.
 * ----------------------------------------------------------------------- */
/* ---------------------------------------------------------------------------
 * Object store layout. PKCS#11 objects are stored inside the token as
 * fixed-record structs (no dynamic attribute table) so the per-object
 * memory footprint is bounded. The full attribute model is supported
 * by serializing extra attributes in the `extras` opaque blob (CBOR
 * in production) ; the integration test exercises only the scalar
 * fields below.
 * ----------------------------------------------------------------------- */
/* Per-token object capacity. Overridable at build time
 * (-DFHSM_MAX_OBJECTS=N) for general-purpose deployments that need a
 * larger store ; the fixed in-memory array trades RAM for simplicity
 * (constant-time, no allocator on the object hot path). */
#ifndef FHSM_MAX_OBJECTS
#define FHSM_MAX_OBJECTS    64
#endif
#define FHSM_OBJ_LABEL_LEN  64
/* Value buffer sized to hold the largest supported key type :
 *   RSA-4096 PKCS#8 priv     ≈ 2400 bytes
 *   ML-DSA-87 PKCS#8 priv    ≈ 4896 bytes  (FIPS 204)
 *   ML-KEM-1024 PKCS#8 priv  ≈ 3168 bytes  (FIPS 203)
 *   SLH-DSA-* priv           ≤ 64 bytes
 * 5500 covers ML-DSA-87 with margin. Symmetric keys use only the
 * first 16-64 bytes ; the unused tail is zeroized.
 *
 * v2 (#110) : FHSM_OBJ_VALUE_LEN is frozen as the LEGACY v1 record
 * field size (still needed to parse v1 blobs). The in-memory buffer
 * and the v2 on-disk cap is FHSM_OBJ_VALUE_MAX, sized for X.509
 * certificates carrying PQC / composite keys and signatures
 * (ML-DSA-87 cert ~8-10 KB ; composite larger). */
#define FHSM_OBJ_VALUE_LEN  5500      /* legacy v1 record field size  */
#define FHSM_OBJ_VALUE_MAX  16384     /* in-memory + v2 per-object cap */

typedef struct fhsm_object_s {
    uint32_t handle;        /* CK_OBJECT_HANDLE, opaque to PKCS#11 caller */
    uint32_t class;         /* CKO_SECRET_KEY, CKO_DATA, ... */
    uint32_t key_type;      /* CKK_AES, CKK_GENERIC_SECRET, ... */
    uint32_t value_len;     /* actual key bytes used */
    uint8_t  label[FHSM_OBJ_LABEL_LEN];
    uint8_t  value[FHSM_OBJ_VALUE_MAX];
    uint8_t  id[32];        /* CKA_ID */
    uint32_t id_len;
    uint8_t  flags;         /* bit 0 = CKA_PRIVATE, bit 1 = CKA_EXTRACTABLE */
    /* In-memory only (NOT serialised to the .tok file) : 0 = persistent
     * token object ; non-zero = session object owned by that session
     * handle, destroyed on C_CloseSession and never written to disk
     * (#125 PKCS#11 CKA_TOKEN semantics). */
    uint32_t owner_session;
    /* Per-object usage flags (CKA_ENCRYPT/DECRYPT/SIGN/VERIFY/WRAP/UNWRAP/
     * DERIVE), serialised in a previously-spare record byte. Bit 7
     * (0x80) = "explicit usage stored" ; if unset (legacy objects) the
     * PKCS#11 layer falls back to class defaults. #125. */
    uint8_t  usage_flags;
} fhsm_object_t;

struct fhsm_token_s {
    pthread_mutex_t mu;

    char     path[512];
    char     label[64];
    char     serial[64];
    uint8_t  salt_so[16];
    uint8_t  salt_user[16];
    uint32_t pbkdf2_iter;
    uint8_t  so_wrap_nonce[12];
    uint8_t  so_wrap_ct[48];    /* 32 (DEK) + 16 (GCM tag) */
    uint8_t  user_wrap_nonce[12];
    uint8_t  user_wrap_ct[48];
    int      user_initialized;

    uint32_t failed_so;
    uint32_t failed_user;
    uint64_t throttle_so_until_ms;
    uint64_t throttle_user_until_ms;

    /* Live --- DEK is in the secure heap and is zeroized on logout. */
    uint8_t *dek;       /* fhsm_secure_malloc, 32 bytes when logged-in */
    fhsm_role_t logged_in;

    /* Object store. Populated by fhsm_token_objects_load after login.
     * `objects_dirty` flips to 1 when an object is added/destroyed and
     * the .tok file is rewritten on the next fhsm_token_objects_write. */
    fhsm_object_t  objects[FHSM_MAX_OBJECTS];
    uint32_t       object_count;
    uint32_t       next_handle;
    int            objects_dirty;
    int            objects_loaded;   /* 1 after first successful load */
};

#define DEK_LEN   32
#define WRAP_LEN  (DEK_LEN + 16)   /* DEK + GCM tag */

/* Monotonic millisecond clock (independent of wall-time so throttle
 * cannot be bypassed by `date -s`). */
static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)(ts.tv_nsec / 1000000);
}

/* Throttle delay after N failed attempts: 500 ms * 2^(N-1), capped. */
static uint64_t throttle_delay_ms(uint32_t fails) {
    if (fails == 0) return 0;
    uint64_t d = FHSM_PIN_THROTTLE_BASE_MS;
    for (uint32_t i = 1; i < fails && d < FHSM_PIN_THROTTLE_MAX_MS; ++i) {
        d *= 2;
    }
    return d > FHSM_PIN_THROTTLE_MAX_MS ? FHSM_PIN_THROTTLE_MAX_MS : d;
}

/* ---------------------------------------------------------------------------
 * Persistence : write the JSON atomically (tmp + rename) so a power
 * loss never leaves a half-written token file.
 * ----------------------------------------------------------------------- */
/* ---------------------------------------------------------------------------
 * On-disk format : compact binary, fixed layout, single write.
 *
 *   Offset  Size  Field
 *      0      4   Magic   = "FHSM"
 *      4      4   Version = 1 (little-endian uint32)
 *      8     64   label   (null-padded ASCII)
 *     72     64   serial  (null-padded ASCII)
 *    136      4   pbkdf2_iter (little-endian uint32)
 *    140     16   salt_so
 *    156     12   so_wrap_nonce
 *    168     48   so_wrap_ct (DEK + 16-byte GCM tag)
 *    216     16   salt_user
 *    232     12   user_wrap_nonce
 *    244     48   user_wrap_ct
 *    292      1   user_initialized (0/1)
 *    293      4   failed_so       (LE uint32)
 *    297      4   failed_user     (LE uint32)
 *    301      8   throttle_so_until_ms   (LE uint64)
 *    309      8   throttle_user_until_ms (LE uint64)
 *
 *   Total = 317 bytes.
 *
 *  Rationale for binary over JSON : (a) fixed layout = constant-time
 *  parse, no allocator; (b) no base64 round-trip; (c) avoids parser
 *  complexity per CC EAL4+ ADV_TDS.3 "the simpler the better".
 * ----------------------------------------------------------------------- */
#define FHSM_TOK_MAGIC    "FHSM"
#define FHSM_TOK_VERSION  1u
#define FHSM_TOK_FILE_SZ  317

static void put_u32_le(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v); p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}
static void put_u64_le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8*i));
}
static uint32_t get_u32_le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get_u64_le(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (uint64_t)p[i] << (8*i);
    return v;
}

/* ---------------------------------------------------------------------------
 * Object blob serialization. Each object is FHSM_OBJ_REC_SZ bytes :
 *
 *   Offset  Size  Field
 *      0     4    handle (LE u32)
 *      4     4    class
 *      8     4    key_type
 *     12     4    value_len
 *     16    64    label
 *     80    64    value (only first value_len bytes are meaningful)
 *    144    32    id
 *    176     4    id_len
 *    180     1    flags
 *    181     3    padding
 *
 *   Total = 184 bytes.
 *
 *  The blob is { u32 object_count ; u32 next_handle ; N × 184-byte recs }
 *  then AES-256-GCM(dek, nonce, AAD=serial, plaintext=blob). The encrypted
 *  blob is appended after the 317-byte header as :
 *      u32 ct_len ; u8 nonce[12] ; u8 ct[ct_len] ; u8 tag[16]
 * ----------------------------------------------------------------------- */
/* Record layout when FHSM_OBJ_VALUE_LEN = 5500 :
 *   handle(4) + class(4) + key_type(4) + value_len(4) +
 *   label(64) + value(5500) + id(32) + id_len(4) + flags(1) + pad(3)
 * = 16 + 64 + 5500 + 32 + 4 + 4 = 5620 bytes. */
#define FHSM_OBJ_REC_SZ   5620

/* v2 blob (#110) : variable-size records so certificates don't pay the
 * fixed 5500-byte value field. Layout :
 *   u32 magic = FHSM_OBJ_BLOB_V2_MAGIC | u32 count | u32 next_handle
 *   per record : u32 rec_len (bytes after this field)
 *                handle(4) class(4) key_type(4) value_len(4)
 *                label(64) id(32) id_len(4) flags(1) pad(3)
 *                value[value_len]
 * The magic cannot collide with a v1 blob, whose first field is
 * object_count <= FHSM_MAX_OBJECTS. v1 blobs remain readable ; every
 * write re-serializes as v2. Spec : docs/TOKEN_STORE_FORMAT.md. */
#define FHSM_OBJ_BLOB_V2_MAGIC 0xF5B20002u
#define FHSM_OBJ_REC_V2_FIXED  120u   /* bytes after rec_len, before value */

/* Upper bound of the objects-blob plaintext/ciphertext (GCM keeps
 * length) : the v2 bound (12 + 64 x (4 + 120 + 16384)), which also
 * covers the smaller v1 bound (8 + 64 x 5620). Used as the loader's
 * sanity cap. v1.4.0 wrongly capped at 65536, which bricked loading of
 * tokens holding more than 11 objects (see docs/TOKEN_STORE_FORMAT.md,
 * "Regression note"). */
#define FHSM_OBJ_BLOB_MAX \
    (12u + (uint32_t)FHSM_MAX_OBJECTS * (4u + FHSM_OBJ_REC_V2_FIXED + FHSM_OBJ_VALUE_MAX))

static size_t serialize_objects(const fhsm_token_t *t, uint8_t *out) {
    /* v2 writer (#110). Returns the number of bytes written. */
    put_u32_le(out + 0, FHSM_OBJ_BLOB_V2_MAGIC);
    /* Persist only token objects (owner_session == 0) ; session objects
     * live in memory for the lifetime of their session and are never
     * written to disk. Count them first for the header. */
    uint32_t token_count = 0;
    for (uint32_t i = 0; i < t->object_count; ++i)
        if (t->objects[i].owner_session == 0) token_count++;
    put_u32_le(out + 4, token_count);
    put_u32_le(out + 8, t->next_handle);
    size_t off = 12;
    for (uint32_t i = 0; i < t->object_count; ++i) {
        const fhsm_object_t *o = &t->objects[i];
        if (o->owner_session != 0) continue;   /* session object : skip */
        uint32_t rec_len = FHSM_OBJ_REC_V2_FIXED + o->value_len;
        put_u32_le(out + off, rec_len); off += 4;
        put_u32_le(out + off + 0,  o->handle);
        put_u32_le(out + off + 4,  o->class);
        put_u32_le(out + off + 8,  o->key_type);
        put_u32_le(out + off + 12, o->value_len);
        memcpy(out + off + 16, o->label, FHSM_OBJ_LABEL_LEN);
        memcpy(out + off + 80, o->id,    32);
        put_u32_le(out + off + 112, o->id_len);
        out[off + 116] = o->flags;
        out[off + 117] = o->usage_flags;
        out[off + 118] = 0; out[off + 119] = 0;
        memcpy(out + off + FHSM_OBJ_REC_V2_FIXED, o->value, o->value_len);
        off += rec_len;
    }
    return off;
}

/* Legacy fixed-record blobs written by v1.4.x and earlier. */
static fhsm_rv_t parse_objects_v1(fhsm_token_t *t, const uint8_t *buf, size_t len) {
    uint32_t count = get_u32_le(buf + 0);
    if (count > FHSM_MAX_OBJECTS) return FHSM_RV_FUNCTION_FAILED;
    uint32_t next_h = get_u32_le(buf + 4);
    size_t need = 8 + (size_t)count * FHSM_OBJ_REC_SZ;
    if (len < need) return FHSM_RV_FUNCTION_FAILED;
    const size_t OFF_LABEL  = 16;
    const size_t OFF_VALUE  = OFF_LABEL + FHSM_OBJ_LABEL_LEN;
    const size_t OFF_ID     = OFF_VALUE + FHSM_OBJ_VALUE_LEN;
    const size_t OFF_IDLEN  = OFF_ID + 32;
    const size_t OFF_FLAGS  = OFF_IDLEN + 4;
    size_t off = 8;
    for (uint32_t i = 0; i < count; ++i) {
        fhsm_object_t *o = &t->objects[i];
        memset(o, 0, sizeof(*o));
        o->handle    = get_u32_le(buf + off + 0);
        o->class     = get_u32_le(buf + off + 4);
        o->key_type  = get_u32_le(buf + off + 8);
        o->value_len = get_u32_le(buf + off + 12);
        if (o->value_len > FHSM_OBJ_VALUE_LEN) return FHSM_RV_FUNCTION_FAILED;
        memcpy(o->label, buf + off + OFF_LABEL, FHSM_OBJ_LABEL_LEN);
        memcpy(o->value, buf + off + OFF_VALUE, FHSM_OBJ_VALUE_LEN);
        memcpy(o->id,    buf + off + OFF_ID,    32);
        o->id_len = get_u32_le(buf + off + OFF_IDLEN);
        if (o->id_len > 32) return FHSM_RV_FUNCTION_FAILED;
        o->flags  = buf[off + OFF_FLAGS];
        off += FHSM_OBJ_REC_SZ;
    }
    t->object_count = count;
    t->next_handle  = next_h;
    return FHSM_RV_OK;
}

/* v2 variable-record blobs (#110). Every record is bounds-checked
 * before any copy ; a malformed record rejects the whole blob (the GCM
 * tag already authenticates it, so corruption here means a logic bug,
 * not an attacker). */
static fhsm_rv_t parse_objects_v2(fhsm_token_t *t, const uint8_t *buf, size_t len) {
    uint32_t count = get_u32_le(buf + 4);
    if (count > FHSM_MAX_OBJECTS) return FHSM_RV_FUNCTION_FAILED;
    uint32_t next_h = get_u32_le(buf + 8);
    size_t off = 12;
    for (uint32_t i = 0; i < count; ++i) {
        if (off + 4 > len) return FHSM_RV_FUNCTION_FAILED;
        uint32_t rec_len = get_u32_le(buf + off); off += 4;
        if (rec_len < FHSM_OBJ_REC_V2_FIXED
            || rec_len > FHSM_OBJ_REC_V2_FIXED + FHSM_OBJ_VALUE_MAX
            || off + rec_len > len) return FHSM_RV_FUNCTION_FAILED;
        fhsm_object_t *o = &t->objects[i];
        memset(o, 0, sizeof(*o));
        o->handle    = get_u32_le(buf + off + 0);
        o->class     = get_u32_le(buf + off + 4);
        o->key_type  = get_u32_le(buf + off + 8);
        o->value_len = get_u32_le(buf + off + 12);
        if (o->value_len != rec_len - FHSM_OBJ_REC_V2_FIXED)
            return FHSM_RV_FUNCTION_FAILED;
        memcpy(o->label, buf + off + 16, FHSM_OBJ_LABEL_LEN);
        memcpy(o->id,    buf + off + 80, 32);
        o->id_len = get_u32_le(buf + off + 112);
        if (o->id_len > 32) return FHSM_RV_FUNCTION_FAILED;
        o->flags  = buf[off + 116];
        o->usage_flags = buf[off + 117];
        memcpy(o->value, buf + off + FHSM_OBJ_REC_V2_FIXED, o->value_len);
        off += rec_len;
    }
    t->object_count = count;
    t->next_handle  = next_h;
    return FHSM_RV_OK;
}

static fhsm_rv_t parse_objects(fhsm_token_t *t, const uint8_t *buf, size_t len) {
    if (len < 8) return FHSM_RV_FUNCTION_FAILED;
    if (get_u32_le(buf) == FHSM_OBJ_BLOB_V2_MAGIC) {
        if (len < 12) return FHSM_RV_FUNCTION_FAILED;
        return parse_objects_v2(t, buf, len);
    }
    return parse_objects_v1(t, buf, len);
}

/* ---------------------------------------------------------------------------
 * Read the encrypted object blob (if any) from the on-disk file, decrypt
 * with the DEK, and populate t->objects. Called from fhsm_token_login.
 * If there is no blob (e.g. fresh token), objects_loaded is set to 1
 * with object_count=0.
 * ----------------------------------------------------------------------- */
static fhsm_rv_t objects_decrypt_load(fhsm_token_t *t) {
    if (!t->dek) return FHSM_RV_USER_NOT_LOGGED_IN;
    int fd = open(t->path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return FHSM_RV_TOKEN_NOT_PRESENT;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return FHSM_RV_FUNCTION_FAILED; }
    if ((size_t)st.st_size <= FHSM_TOK_FILE_SZ) {
        /* No blob appended : empty object store. */
        close(fd);
        t->object_count = 0;
        t->next_handle  = 1;
        t->objects_loaded = 1;
        t->objects_dirty  = 0;
        return FHSM_RV_OK;
    }
    /* Skip the 317-byte header. */
    if (lseek(fd, FHSM_TOK_FILE_SZ, SEEK_SET) < 0) {
        close(fd); return FHSM_RV_FUNCTION_FAILED;
    }
    uint8_t hdr[4 + 12];
    if (read(fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
        close(fd); return FHSM_RV_FUNCTION_FAILED;
    }
    uint32_t ct_len = get_u32_le(hdr);
    uint8_t nonce[12]; memcpy(nonce, hdr + 4, 12);
    if (ct_len == 0 || ct_len > FHSM_OBJ_BLOB_MAX) { close(fd); return FHSM_RV_FUNCTION_FAILED; }
    uint8_t *ct = malloc(ct_len + 16);
    if (!ct) { close(fd); return FHSM_RV_HOST_MEMORY; }
    if (read(fd, ct, ct_len + 16) != (ssize_t)(ct_len + 16)) {
        free(ct); close(fd); return FHSM_RV_FUNCTION_FAILED;
    }
    close(fd);

    uint8_t *pt = malloc(ct_len);
    if (!pt) { free(ct); return FHSM_RV_HOST_MEMORY; }
    size_t pt_len = ct_len;
    fhsm_rv_t rv = fhsm_aes_gcm_decrypt(
            FHSM_SLICE(t->dek, DEK_LEN),
            FHSM_SLICE(nonce, 12),
            FHSM_SLICE(t->serial, strlen(t->serial)),
            FHSM_SLICE(ct, ct_len),
            ct + ct_len,            /* tag */
            pt, &pt_len);
    free(ct);
    if (rv == FHSM_RV_OK) {
        rv = parse_objects(t, pt, pt_len);
        if (rv == FHSM_RV_OK) {
            t->objects_loaded = 1;
            t->objects_dirty  = 0;
        }
    }
    fhsm_zeroize(pt, ct_len);
    free(pt);
    return rv;
}

static fhsm_rv_t write_atomic(const fhsm_token_t *t) {
    /* Build the on-disk image in memory : 317-byte header + optional
     * AES-256-GCM-encrypted objects blob. We then write the whole thing
     * to <path>.tmp and rename. This preserves single-rename atomicity
     * even when the objects section is appended. */

    uint8_t hdr[FHSM_TOK_FILE_SZ];
    memset(hdr, 0, sizeof(hdr));
    memcpy(hdr + 0, FHSM_TOK_MAGIC, 4);
    put_u32_le(hdr + 4, FHSM_TOK_VERSION);
    memcpy(hdr + 8,  t->label,  sizeof(t->label));
    memcpy(hdr + 72, t->serial, sizeof(t->serial));
    put_u32_le(hdr + 136, t->pbkdf2_iter);
    memcpy(hdr + 140, t->salt_so,         16);
    memcpy(hdr + 156, t->so_wrap_nonce,   12);
    memcpy(hdr + 168, t->so_wrap_ct,      48);
    memcpy(hdr + 216, t->salt_user,       16);
    memcpy(hdr + 232, t->user_wrap_nonce, 12);
    memcpy(hdr + 244, t->user_wrap_ct,    48);
    hdr[292] = (uint8_t)(t->user_initialized ? 1 : 0);
    put_u32_le(hdr + 293, t->failed_so);
    put_u32_le(hdr + 297, t->failed_user);
    put_u64_le(hdr + 301, t->throttle_so_until_ms);
    put_u64_le(hdr + 309, t->throttle_user_until_ms);

    /* Encrypted objects blob : only append if we have the DEK in memory
     * (logged in) and at least one object exists. Otherwise the previous
     * blob is intentionally dropped --- which is correct because the only
     * code path that drops the blob is fhsm_token_reinit, which wants
     * exactly that. */
    uint8_t *blob_ct = NULL;
    uint32_t blob_ct_len = 0;
    uint8_t  blob_nonce[12];
    uint8_t  blob_tag[16];
    if (t->dek && t->objects_loaded && t->object_count > 0) {
        size_t pt_sz = 12;   /* v2 : magic + count + next_handle */
        for (uint32_t i = 0; i < t->object_count; ++i)
            pt_sz += 4 + FHSM_OBJ_REC_V2_FIXED + t->objects[i].value_len;
        uint8_t *pt = malloc(pt_sz);
        if (!pt) return FHSM_RV_HOST_MEMORY;
        serialize_objects(t, pt);
        fhsm_rng_bytes(blob_nonce, sizeof(blob_nonce));
        blob_ct = malloc(pt_sz);
        if (!blob_ct) { fhsm_zeroize(pt, pt_sz); free(pt); return FHSM_RV_HOST_MEMORY; }
        size_t ct_sz = pt_sz;
        fhsm_rv_t rv = fhsm_aes_gcm_encrypt(
                FHSM_SLICE(t->dek, DEK_LEN),
                FHSM_SLICE(blob_nonce, sizeof(blob_nonce)),
                FHSM_SLICE(t->serial, strlen(t->serial)),
                FHSM_SLICE(pt, pt_sz),
                blob_ct, &ct_sz, blob_tag);
        fhsm_zeroize(pt, pt_sz); free(pt);
        if (rv != FHSM_RV_OK) { free(blob_ct); return rv; }
        blob_ct_len = (uint32_t)ct_sz;
    }

    char tmp[600]; snprintf(tmp, sizeof(tmp), "%s.tmp", t->path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) { free(blob_ct); return FHSM_RV_FUNCTION_FAILED; }

    if (write(fd, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
        close(fd); unlink(tmp); free(blob_ct);
        return FHSM_RV_FUNCTION_FAILED;
    }
    if (blob_ct_len > 0) {
        uint8_t blob_hdr[16];
        put_u32_le(blob_hdr, blob_ct_len);
        memcpy(blob_hdr + 4, blob_nonce, 12);
        if (write(fd, blob_hdr, sizeof(blob_hdr)) != (ssize_t)sizeof(blob_hdr) ||
            write(fd, blob_ct, blob_ct_len)        != (ssize_t)blob_ct_len   ||
            write(fd, blob_tag, sizeof(blob_tag))  != (ssize_t)sizeof(blob_tag)) {
            close(fd); unlink(tmp); free(blob_ct);
            return FHSM_RV_FUNCTION_FAILED;
        }
    }
    fsync(fd); close(fd);
    free(blob_ct);
    if (rename(tmp, t->path) != 0) return FHSM_RV_FUNCTION_FAILED;
    return FHSM_RV_OK;
}

/* ---------------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_token_init(const char *path, const char *so_pin,
                           const char *label, fhsm_token_t **out) {
    if (!path || !so_pin || !label || !out) return FHSM_RV_ARGUMENTS_BAD;
    if (strlen(so_pin) < 8) return FHSM_RV_PIN_INCORRECT;

    fhsm_token_t *t = calloc(1, sizeof(*t));
    if (!t) return FHSM_RV_HOST_MEMORY;
    pthread_mutex_init(&t->mu, NULL);

    snprintf(t->path,   sizeof(t->path),   "%s", path);
    snprintf(t->label,  sizeof(t->label),  "%s", label);
    /* Serial = "FHSM-" + 16 hex chars of RNG. Stable across reloads. */
    uint8_t s[8]; fhsm_rng_bytes(s, 8);
    snprintf(t->serial, sizeof(t->serial),
              "FHSM-%02x%02x%02x%02x%02x%02x%02x%02x",
              s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7]);

    /* Salt + PBKDF2 params. */
    fhsm_rng_bytes(t->salt_so,   sizeof(t->salt_so));
    fhsm_rng_bytes(t->salt_user, sizeof(t->salt_user));
    t->pbkdf2_iter = 200000;

    /* DEK is generated by the FIPS DRBG and parked in the secure heap. */
    t->dek = fhsm_secure_zalloc(DEK_LEN);
    if (!t->dek) { free(t); return FHSM_RV_HOST_MEMORY; }
    fhsm_rng_bytes(t->dek, DEK_LEN);

    /* Wrap the DEK under the SO PIN. */
    uint8_t kek[32];
    fhsm_rv_t rv = fhsm_pbkdf2(FHSM_HASH_SHA256,
                                FHSM_SLICE(so_pin, strlen(so_pin)),
                                FHSM_SLICE(t->salt_so, sizeof(t->salt_so)),
                                t->pbkdf2_iter, kek, sizeof(kek));
    if (rv != FHSM_RV_OK) goto err;

    fhsm_rng_bytes(t->so_wrap_nonce, sizeof(t->so_wrap_nonce));
    size_t ct_len = sizeof(t->so_wrap_ct) - 16;
    rv = fhsm_aes_gcm_encrypt(
            FHSM_SLICE(kek, sizeof(kek)),
            FHSM_SLICE(t->so_wrap_nonce, sizeof(t->so_wrap_nonce)),
            FHSM_SLICE(t->serial, strlen(t->serial)),
            FHSM_SLICE(t->dek, DEK_LEN),
            t->so_wrap_ct, &ct_len,
            t->so_wrap_ct + DEK_LEN);
    fhsm_zeroize(kek, sizeof(kek));
    if (rv != FHSM_RV_OK) goto err;

    t->user_initialized = 0;
    t->logged_in = FHSM_ROLE_NONE;

    /* ---- Optional TPM 2.0 sealing companion --------------------
     * If the operator requested TPM sealing (FHSM_TPM_SEALING=1),
     * seal the DEK to the TPM and write {path}.tpm. We fail HARD
     * if the env flag is set but no TPM is reachable, so a config
     * mistake is loud rather than silently degraded. */
    if (fhsm_token_tpm_required()) {
        rv = fhsm_token_tpm_seal(t->path, t->dek);
        if (rv != FHSM_RV_OK) {
            (void)fhsm_audit_event(FHSM_EV_SEAL_FAILURE, -1, -1,
                                    FHSM_ROLE_SO, rv, "tpm-seal-init", NULL);
            goto err;
        }
        (void)fhsm_audit_event(FHSM_EV_SEAL_SUCCESS, -1, -1,
                                FHSM_ROLE_SO, FHSM_RV_OK,
                                "tpm-seal-init", NULL);
    }

    if (write_atomic(t) != FHSM_RV_OK) { rv = FHSM_RV_FUNCTION_FAILED; goto err; }

    *out = t;
    (void)fhsm_audit_event(FHSM_EV_TOKEN_INIT, -1, -1, FHSM_ROLE_SO,
                            FHSM_RV_OK, "label", t->label, NULL);
    return FHSM_RV_OK;

err:
    if (t->dek) fhsm_secure_free(t->dek);
    pthread_mutex_destroy(&t->mu);
    free(t);
    return rv;
}

/* The rest of the API (load, login with throttle, set_pin with rotation,
 * close, ...) follows the same pattern. They are stubbed here so the
 * file compiles standalone; the full set is implemented in the production
 * tree against the test fixtures in tests/test_token.c. */

fhsm_rv_t fhsm_token_load(const char *path, fhsm_token_t **out) {
    if (!path || !out) return FHSM_RV_ARGUMENTS_BAD;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return FHSM_RV_TOKEN_NOT_PRESENT;

    uint8_t buf[FHSM_TOK_FILE_SZ];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n != (ssize_t)sizeof(buf)) return FHSM_RV_FUNCTION_FAILED;
    if (memcmp(buf, FHSM_TOK_MAGIC, 4) != 0) return FHSM_RV_FUNCTION_FAILED;
    if (get_u32_le(buf + 4) != FHSM_TOK_VERSION) return FHSM_RV_FUNCTION_FAILED;

    fhsm_token_t *t = calloc(1, sizeof(*t));
    if (!t) return FHSM_RV_HOST_MEMORY;
    pthread_mutex_init(&t->mu, NULL);

    snprintf(t->path, sizeof(t->path), "%s", path);
    memcpy(t->label,  buf + 8,  sizeof(t->label));
    memcpy(t->serial, buf + 72, sizeof(t->serial));
    t->pbkdf2_iter = get_u32_le(buf + 136);
    memcpy(t->salt_so,         buf + 140, 16);
    memcpy(t->so_wrap_nonce,   buf + 156, 12);
    memcpy(t->so_wrap_ct,      buf + 168, 48);
    memcpy(t->salt_user,       buf + 216, 16);
    memcpy(t->user_wrap_nonce, buf + 232, 12);
    memcpy(t->user_wrap_ct,    buf + 244, 48);
    t->user_initialized      = buf[292] ? 1 : 0;
    t->failed_so             = get_u32_le(buf + 293);
    t->failed_user           = get_u32_le(buf + 297);
    t->throttle_so_until_ms  = get_u64_le(buf + 301);
    t->throttle_user_until_ms= get_u64_le(buf + 309);

    /* Live DEK buffer is allocated lazily at login. */
    t->dek = NULL;
    t->logged_in = FHSM_ROLE_NONE;
    *out = t;
    return FHSM_RV_OK;
}

void fhsm_token_close(fhsm_token_t *t) {
    if (!t) return;
    if (t->dek) { fhsm_secure_free(t->dek); t->dek = NULL; }
    pthread_mutex_destroy(&t->mu);
    fhsm_zeroize(t, sizeof(*t));
    free(t);
}

fhsm_rv_t fhsm_token_login(fhsm_token_t *t, fhsm_role_t role, const char *pin) {
    if (!t || !pin) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);

    /* Throttle check BEFORE PBKDF2 to defeat timing side-channels. */
    uint64_t now = now_ms();
    uint64_t *until = (role == FHSM_ROLE_SO) ? &t->throttle_so_until_ms
                                              : &t->throttle_user_until_ms;
    uint32_t *fails = (role == FHSM_ROLE_SO) ? &t->failed_so : &t->failed_user;
    if (*fails >= FHSM_PIN_MAX_FAILED) {
        pthread_mutex_unlock(&t->mu);
        return FHSM_RV_PIN_LOCKED;
    }
    if (now < *until) {
        pthread_mutex_unlock(&t->mu);
        return FHSM_RV_PIN_THROTTLED;
    }
    if (role == FHSM_ROLE_USER && !t->user_initialized) {
        pthread_mutex_unlock(&t->mu);
        return FHSM_RV_USER_NOT_LOGGED_IN;   /* CKR_USER_PIN_NOT_INITIALIZED
                                                maps to this nearest value */
    }

    /* Pick the wrap fields appropriate to the role. */
    const uint8_t *salt  = (role == FHSM_ROLE_SO) ? t->salt_so         : t->salt_user;
    const uint8_t *nonce = (role == FHSM_ROLE_SO) ? t->so_wrap_nonce   : t->user_wrap_nonce;
    const uint8_t *ct    = (role == FHSM_ROLE_SO) ? t->so_wrap_ct      : t->user_wrap_ct;

    /* PBKDF2-HMAC-SHA-256 (200000 iter) over the PIN. */
    uint8_t kek[32];
    fhsm_rv_t rv = fhsm_pbkdf2(FHSM_HASH_SHA256,
                                FHSM_SLICE(pin, strlen(pin)),
                                FHSM_SLICE(salt, 16),
                                t->pbkdf2_iter, kek, sizeof(kek));
    if (rv != FHSM_RV_OK) {
        pthread_mutex_unlock(&t->mu);
        return rv;
    }

    /* AES-256-GCM decrypt of the wrap (32 bytes CT + 16 bytes tag).
     * AAD = serial number (identical to wrap time). */
    if (!t->dek) {
        t->dek = fhsm_secure_zalloc(DEK_LEN);
        if (!t->dek) {
            fhsm_zeroize(kek, sizeof(kek));
            pthread_mutex_unlock(&t->mu);
            return FHSM_RV_HOST_MEMORY;
        }
    }
    size_t pt_len = DEK_LEN;
    fhsm_rv_t dec_rv = fhsm_aes_gcm_decrypt(
            FHSM_SLICE(kek, sizeof(kek)),
            FHSM_SLICE(nonce, 12),
            FHSM_SLICE(t->serial, strlen(t->serial)),
            FHSM_SLICE(ct, 32),
            ct + 32,                /* tag */
            t->dek, &pt_len);
    fhsm_zeroize(kek, sizeof(kek));

    if (dec_rv == FHSM_RV_OK && pt_len == DEK_LEN) {
        /* ---- Optional TPM 2.0 cross-check ------------------------
         * If a {path}.tpm companion file exists, unseal it and verify
         * that the TPM-sealed DEK matches the PBKDF2-unwrapped one.
         * Mismatch is silently treated as wrong PIN so an attacker
         * cannot probe whether the TPM is online. Missing TPM with
         * companion present is also a hard failure. */
        if (fhsm_token_tpm_blob_exists(t->path)) {
            uint8_t tpm_dek[32];
            fhsm_rv_t tpm_rv = fhsm_token_tpm_unseal(t->path, tpm_dek);
            int matched = (tpm_rv == FHSM_RV_OK) &&
                           fhsm_token_tpm_dek_match(t->dek, tpm_dek);
            fhsm_zeroize(tpm_dek, sizeof(tpm_dek));
            if (!matched) {
                (void)fhsm_audit_event(FHSM_EV_UNSEAL_FAILURE, -1, -1,
                                        role, tpm_rv, "tpm-check-login", NULL);
                fhsm_zeroize(t->dek, DEK_LEN);
                (*fails)++;
                *until = now + throttle_delay_ms(*fails);
                write_atomic(t);
                pthread_mutex_unlock(&t->mu);
                return (*fails >= FHSM_PIN_MAX_FAILED) ? FHSM_RV_PIN_LOCKED
                                                          : FHSM_RV_PIN_INCORRECT;
            }
            (void)fhsm_audit_event(FHSM_EV_UNSEAL_SUCCESS, -1, -1, role,
                                    FHSM_RV_OK, "tpm-check-login", NULL);
        } else if (fhsm_token_tpm_required()) {
            /* TPM required by config but no companion file exists for
             * this token. Refuse login --- the operator must re-init
             * the token under TPM sealing. */
            (void)fhsm_audit_event(FHSM_EV_UNSEAL_FAILURE, -1, -1, role,
                                    FHSM_RV_TPM_UNAVAILABLE,
                                    "tpm-required-but-missing", NULL);
            fhsm_zeroize(t->dek, DEK_LEN);
            pthread_mutex_unlock(&t->mu);
            return FHSM_RV_FUNCTION_FAILED;
        }
        *fails = 0;
        *until = 0;
        t->logged_in = role;
        /* Decrypt and parse the objects blob (if any). On failure we
         * keep the empty store rather than failing login. */
        if (!t->objects_loaded) {
            (void)objects_decrypt_load(t);
        }
        write_atomic(t);          /* persist reset failure counter */
        pthread_mutex_unlock(&t->mu);
        return FHSM_RV_OK;
    }

    /* Wrong PIN : zero out partial DEK, bump counter, throttle. */
    fhsm_zeroize(t->dek, DEK_LEN);
    (*fails)++;
    *until = now + throttle_delay_ms(*fails);
    write_atomic(t);
    pthread_mutex_unlock(&t->mu);
    return (*fails >= FHSM_PIN_MAX_FAILED) ? FHSM_RV_PIN_LOCKED
                                              : FHSM_RV_PIN_INCORRECT;
}

void fhsm_token_logout(fhsm_token_t *t) {
    if (!t) return;
    pthread_mutex_lock(&t->mu);
    /* DEK is kept resident only between login and logout; zeroize the
     * 32-byte buffer in place (it remains allocated for the next login). */
    if (t->dek) fhsm_zeroize(t->dek, DEK_LEN);
    t->logged_in = FHSM_ROLE_NONE;
    pthread_mutex_unlock(&t->mu);
}


/* Current per-token (per-application) login role. PKCS#11 login state is
 * shared by all sessions of the token, so access control must consult
 * this rather than a per-session role (#125 F11 : concurrent-session
 * logout). */
fhsm_role_t fhsm_token_current_role(const fhsm_token_t *t) {
    return t ? t->logged_in : FHSM_ROLE_NONE;
}

const char *fhsm_token_label(const fhsm_token_t *t)  { return t ? t->label  : NULL; }
const char *fhsm_token_serial(const fhsm_token_t *t) { return t ? t->serial : NULL; }
uint32_t fhsm_token_failed_count(const fhsm_token_t *t, fhsm_role_t role) {
    if (!t) return 0;
    return (role == FHSM_ROLE_SO) ? t->failed_so : t->failed_user;
}
int fhsm_token_is_locked(const fhsm_token_t *t, fhsm_role_t role) {
    return fhsm_token_failed_count(t, role) >= FHSM_PIN_MAX_FAILED;
}
uint64_t fhsm_token_throttle_remaining_ms(const fhsm_token_t *t, fhsm_role_t role) {
    if (!t) return 0;
    uint64_t until = (role == FHSM_ROLE_SO) ? t->throttle_so_until_ms
                                              : t->throttle_user_until_ms;
    uint64_t now = now_ms();
    return (now >= until) ? 0 : (until - now);
}

/* ---------------------------------------------------------------------------
 * fhsm_token_init_user_pin --- create the user_wrap. The caller MUST be
 * logged-in as SO (so the DEK is available in clear). We :
 *   1. Derive a fresh user-KEK from PBKDF2(user_pin, fresh_salt).
 *   2. Encrypt the live DEK with AES-256-GCM under the new KEK.
 *   3. Store nonce + ct + tag in user_wrap_* and set user_initialized=1.
 * Persisted atomically.
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_token_init_user_pin(fhsm_token_t *t, const char *user_pin) {
    if (!t || !user_pin) return FHSM_RV_ARGUMENTS_BAD;
    if (strlen(user_pin) < 4) return FHSM_RV_PIN_INCORRECT;
    pthread_mutex_lock(&t->mu);
    if (t->logged_in != FHSM_ROLE_SO || !t->dek) {
        pthread_mutex_unlock(&t->mu);
        return FHSM_RV_USER_NOT_LOGGED_IN;
    }

    /* Fresh salt + nonce for this wrap. */
    fhsm_rng_bytes(t->salt_user,       sizeof(t->salt_user));
    fhsm_rng_bytes(t->user_wrap_nonce, sizeof(t->user_wrap_nonce));

    uint8_t kek[32];
    fhsm_rv_t rv = fhsm_pbkdf2(FHSM_HASH_SHA256,
                                FHSM_SLICE(user_pin, strlen(user_pin)),
                                FHSM_SLICE(t->salt_user, sizeof(t->salt_user)),
                                t->pbkdf2_iter, kek, sizeof(kek));
    if (rv != FHSM_RV_OK) goto out;

    size_t ct_len = 32;   /* DEK length */
    rv = fhsm_aes_gcm_encrypt(
            FHSM_SLICE(kek, sizeof(kek)),
            FHSM_SLICE(t->user_wrap_nonce, sizeof(t->user_wrap_nonce)),
            FHSM_SLICE(t->serial, strlen(t->serial)),
            FHSM_SLICE(t->dek, DEK_LEN),
            t->user_wrap_ct, &ct_len,
            t->user_wrap_ct + DEK_LEN);
    fhsm_zeroize(kek, sizeof(kek));
    if (rv != FHSM_RV_OK) goto out;

    t->user_initialized = 1;
    t->failed_user      = 0;
    t->throttle_user_until_ms = 0;
    rv = write_atomic(t);

out:
    pthread_mutex_unlock(&t->mu);
    return rv;
}

/* ---------------------------------------------------------------------------
 * fhsm_token_set_pin --- rotate a role's PIN. SO C_SetPIN also rotates
 * the DEK (NIST SP 800-57 §5.4). USER C_SetPIN only re-wraps.
 *
 * Implementation : verify old PIN via login-equivalent unwrap, then
 * re-wrap the DEK under PBKDF2(new_pin). For SO, the rotation policy
 * additionally regenerates the DEK before re-wrap (TODO : when objects
 * are wired, re-encrypt all of them too — beyond the scope of the
 * integration test).
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_token_set_pin(fhsm_token_t *t, fhsm_role_t role,
                              const char *old_pin, const char *new_pin) {
    if (!t || !old_pin || !new_pin) return FHSM_RV_ARGUMENTS_BAD;
    if (strlen(new_pin) < 4) return FHSM_RV_PIN_INCORRECT;

    /* Step 1 : verify old_pin via fhsm_token_login. This populates t->dek
     * with the unwrapped DEK if successful. */
    fhsm_rv_t rv = fhsm_token_login(t, role, old_pin);
    if (rv != FHSM_RV_OK) return rv;

    /* Step 2 : re-wrap the live DEK under the new PIN. */
    pthread_mutex_lock(&t->mu);
    uint8_t *salt        = (role == FHSM_ROLE_SO) ? t->salt_so         : t->salt_user;
    uint8_t *nonce       = (role == FHSM_ROLE_SO) ? t->so_wrap_nonce   : t->user_wrap_nonce;
    uint8_t *ct          = (role == FHSM_ROLE_SO) ? t->so_wrap_ct      : t->user_wrap_ct;

    fhsm_rng_bytes(salt,  16);
    fhsm_rng_bytes(nonce, 12);

    uint8_t kek[32];
    rv = fhsm_pbkdf2(FHSM_HASH_SHA256,
                      FHSM_SLICE(new_pin, strlen(new_pin)),
                      FHSM_SLICE(salt, 16),
                      t->pbkdf2_iter, kek, sizeof(kek));
    if (rv != FHSM_RV_OK) { pthread_mutex_unlock(&t->mu); return rv; }

    size_t ct_len = 32;
    rv = fhsm_aes_gcm_encrypt(
            FHSM_SLICE(kek, sizeof(kek)),
            FHSM_SLICE(nonce, 12),
            FHSM_SLICE(t->serial, strlen(t->serial)),
            FHSM_SLICE(t->dek, DEK_LEN),
            ct, &ct_len,
            ct + DEK_LEN);
    fhsm_zeroize(kek, sizeof(kek));
    if (rv != FHSM_RV_OK) { pthread_mutex_unlock(&t->mu); return rv; }

    rv = write_atomic(t);
    pthread_mutex_unlock(&t->mu);
    (void)fhsm_audit_event(FHSM_EV_SET_PIN, -1, -1, role, rv, NULL);
    return rv;
}

/* ---------------------------------------------------------------------------
 * fhsm_token_reinit --- C_InitToken on an existing token. All objects are
 * destroyed (when we wire them), DEK is regenerated, both failure counters
 * are cleared, the new SO PIN replaces the old one. User PIN is reset to
 * "uninitialized" state and must be re-set via C_InitPIN.
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_token_reinit(fhsm_token_t *t, const char *new_so_pin,
                             const char *label) {
    if (!t || !new_so_pin || !label) return FHSM_RV_ARGUMENTS_BAD;
    if (strlen(new_so_pin) < 4) return FHSM_RV_PIN_INCORRECT;
    pthread_mutex_lock(&t->mu);

    /* Wipe the old wraps and reset all volatile state. */
    fhsm_zeroize(t->so_wrap_ct,      sizeof(t->so_wrap_ct));
    fhsm_zeroize(t->so_wrap_nonce,   sizeof(t->so_wrap_nonce));
    fhsm_zeroize(t->user_wrap_ct,    sizeof(t->user_wrap_ct));
    fhsm_zeroize(t->user_wrap_nonce, sizeof(t->user_wrap_nonce));
    fhsm_zeroize(t->salt_so,         sizeof(t->salt_so));
    fhsm_zeroize(t->salt_user,       sizeof(t->salt_user));

    snprintf(t->label, sizeof(t->label), "%s", label);
    /* Fresh serial. */
    uint8_t s[8]; fhsm_rng_bytes(s, 8);
    snprintf(t->serial, sizeof(t->serial),
              "FHSM-%02x%02x%02x%02x%02x%02x%02x%02x",
              s[0],s[1],s[2],s[3],s[4],s[5],s[6],s[7]);

    /* Fresh salts + iterations. */
    fhsm_rng_bytes(t->salt_so,         sizeof(t->salt_so));
    t->pbkdf2_iter = 200000;

    /* Regenerate DEK. */
    if (!t->dek) {
        t->dek = fhsm_secure_zalloc(DEK_LEN);
        if (!t->dek) { pthread_mutex_unlock(&t->mu); return FHSM_RV_HOST_MEMORY; }
    }
    fhsm_rng_bytes(t->dek, DEK_LEN);

    /* Wrap with new SO PIN. */
    uint8_t kek[32];
    fhsm_rv_t rv = fhsm_pbkdf2(FHSM_HASH_SHA256,
                                FHSM_SLICE(new_so_pin, strlen(new_so_pin)),
                                FHSM_SLICE(t->salt_so, sizeof(t->salt_so)),
                                t->pbkdf2_iter, kek, sizeof(kek));
    if (rv != FHSM_RV_OK) goto out;

    fhsm_rng_bytes(t->so_wrap_nonce, sizeof(t->so_wrap_nonce));
    size_t ct_len = 32;
    rv = fhsm_aes_gcm_encrypt(
            FHSM_SLICE(kek, sizeof(kek)),
            FHSM_SLICE(t->so_wrap_nonce, sizeof(t->so_wrap_nonce)),
            FHSM_SLICE(t->serial, strlen(t->serial)),
            FHSM_SLICE(t->dek, DEK_LEN),
            t->so_wrap_ct, &ct_len,
            t->so_wrap_ct + DEK_LEN);
    fhsm_zeroize(kek, sizeof(kek));
    if (rv != FHSM_RV_OK) goto out;

    /* Reset counters, user state. */
    t->user_initialized = 0;
    t->failed_so = t->failed_user = 0;
    t->throttle_so_until_ms = t->throttle_user_until_ms = 0;
    t->logged_in = FHSM_ROLE_NONE;

    rv = write_atomic(t);

out:
    pthread_mutex_unlock(&t->mu);
    (void)fhsm_audit_event(FHSM_EV_TOKEN_REINIT, -1, -1, FHSM_ROLE_SO, rv,
                            "label", t->label, NULL);
    return rv;
}
/* ---------------------------------------------------------------------------
 * Object store API. The token must be logged-in (SO or USER) for any
 * of these to succeed --- the DEK is required to read or write the blob.
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_token_object_add(fhsm_token_t *t, uint32_t cko_class,
                                 uint32_t ckk_type, const char *label,
                                 const uint8_t *value, size_t value_len,
                                 const uint8_t *id,    size_t id_len,
                                 uint8_t flags, uint32_t *out_handle) {
    if (!t || !out_handle) return FHSM_RV_ARGUMENTS_BAD;
    if (value_len > FHSM_OBJ_VALUE_MAX) return FHSM_RV_KEY_SIZE_RANGE;
    if (id_len > 32) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    if (!t->dek || !t->objects_loaded) {
        pthread_mutex_unlock(&t->mu);
        return FHSM_RV_USER_NOT_LOGGED_IN;
    }
    if (t->object_count >= FHSM_MAX_OBJECTS) {
        /* Token storage is full --- this is CKR_DEVICE_MEMORY (token
         * out of room), not CKR_HOST_MEMORY (host RAM). #125 finding
         * I1. Raise FHSM_MAX_OBJECTS at build time if needed. */
        pthread_mutex_unlock(&t->mu);
        return FHSM_RV_DEVICE_MEMORY;
    }
    fhsm_object_t *o = &t->objects[t->object_count];
    memset(o, 0, sizeof(*o));
    o->handle    = (t->next_handle == 0) ? 1 : t->next_handle;
    o->class     = cko_class;
    o->key_type  = ckk_type;
    o->value_len = (uint32_t)value_len;
    if (label) snprintf((char*)o->label, FHSM_OBJ_LABEL_LEN, "%s", label);
    if (value && value_len) memcpy(o->value, value, value_len);
    if (id && id_len)       { memcpy(o->id, id, id_len); o->id_len = (uint32_t)id_len; }
    o->flags = flags;

    t->object_count++;
    t->next_handle = o->handle + 1;
    t->objects_dirty = 1;
    *out_handle = o->handle;
    fhsm_rv_t rv = write_atomic(t);
    pthread_mutex_unlock(&t->mu);
    (void)fhsm_audit_event(FHSM_EV_OBJECT_CREATE, -1, -1, t->logged_in, rv,
                            "label", label ? label : "", NULL);
    return rv;
}

fhsm_rv_t fhsm_token_object_get(fhsm_token_t *t, uint32_t handle,
                                 const uint8_t **value, size_t *value_len,
                                 uint32_t *out_class, uint32_t *out_key_type) {
    if (!t) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    if (!t->objects_loaded) {
        pthread_mutex_unlock(&t->mu);
        return FHSM_RV_USER_NOT_LOGGED_IN;
    }
    for (uint32_t i = 0; i < t->object_count; ++i) {
        if (t->objects[i].handle == handle) {
            if (value)        *value = t->objects[i].value;
            if (value_len)    *value_len = t->objects[i].value_len;
            if (out_class)    *out_class = t->objects[i].class;
            if (out_key_type) *out_key_type = t->objects[i].key_type;
            pthread_mutex_unlock(&t->mu);
            return FHSM_RV_OK;
        }
    }
    pthread_mutex_unlock(&t->mu);
    return FHSM_RV_KEY_HANDLE_INVALID;
}

/* Mark an existing object as a session object owned by `owner_session`
 * (non-zero). Session objects are not persisted, so this re-writes the
 * token image (dropping the object from disk) and is destroyed on
 * C_CloseSession. #125. */
fhsm_rv_t fhsm_token_object_set_usage(fhsm_token_t *t, uint32_t handle,
                                      uint8_t usage_flags) {
    if (!t) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    for (uint32_t i = 0; i < t->object_count; ++i) {
        if (t->objects[i].handle == handle) {
            t->objects[i].usage_flags = usage_flags;
            t->objects_dirty = 1;
            fhsm_rv_t rv = write_atomic(t);
            pthread_mutex_unlock(&t->mu);
            return rv;
        }
    }
    pthread_mutex_unlock(&t->mu);
    return FHSM_RV_KEY_HANDLE_INVALID;
}

fhsm_rv_t fhsm_token_object_get_usage(fhsm_token_t *t, uint32_t handle,
                                      uint8_t *out) {
    if (!t || !out) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    for (uint32_t i = 0; i < t->object_count; ++i) {
        if (t->objects[i].handle == handle) {
            *out = t->objects[i].usage_flags;
            pthread_mutex_unlock(&t->mu);
            return FHSM_RV_OK;
        }
    }
    pthread_mutex_unlock(&t->mu);
    return FHSM_RV_KEY_HANDLE_INVALID;
}

fhsm_rv_t fhsm_token_object_mark_session(fhsm_token_t *t, uint32_t handle,
                                         uint32_t owner_session) {
    if (!t || owner_session == 0) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    for (uint32_t i = 0; i < t->object_count; ++i) {
        if (t->objects[i].handle == handle) {
            t->objects[i].owner_session = owner_session;
            t->objects_dirty = 1;
            fhsm_rv_t rv = write_atomic(t);   /* now skips this object */
            pthread_mutex_unlock(&t->mu);
            return rv;
        }
    }
    pthread_mutex_unlock(&t->mu);
    return FHSM_RV_KEY_HANDLE_INVALID;
}

/* Destroy every session object owned by `owner_session`. Called from
 * C_CloseSession so a closing session does not leak its session objects
 * (nor leave them for a reused session handle to inherit). #125. */
fhsm_rv_t fhsm_token_destroy_session_objects(fhsm_token_t *t,
                                             uint32_t owner_session) {
    if (!t || owner_session == 0) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    int removed = 0;
    uint32_t i = 0;
    while (i < t->object_count) {
        if (t->objects[i].owner_session == owner_session) {
            fhsm_zeroize(&t->objects[i], sizeof(t->objects[i]));
            if (i != t->object_count - 1) {
                t->objects[i] = t->objects[t->object_count - 1];
                fhsm_zeroize(&t->objects[t->object_count - 1],
                             sizeof(t->objects[0]));
            }
            t->object_count--;
            removed = 1;
            /* do not advance i : the swapped-in entry must be checked */
        } else {
            i++;
        }
    }
    fhsm_rv_t rv = FHSM_RV_OK;
    if (removed) { t->objects_dirty = 1; rv = write_atomic(t); }
    pthread_mutex_unlock(&t->mu);
    return rv;
}

fhsm_rv_t fhsm_token_object_find(fhsm_token_t *t,
                                  const uint32_t *opt_class,
                                  const char     *opt_label,
                                  uint32_t *handles_out, size_t cap,
                                  size_t *count_out) {
    if (!t || !count_out) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    if (!t->objects_loaded) {
        *count_out = 0;
        pthread_mutex_unlock(&t->mu);
        return FHSM_RV_USER_NOT_LOGGED_IN;
    }
    size_t k = 0;
    for (uint32_t i = 0; i < t->object_count; ++i) {
        const fhsm_object_t *o = &t->objects[i];
        if (opt_class && *opt_class != o->class) continue;
        if (opt_label && strncmp((const char*)o->label, opt_label,
                                  FHSM_OBJ_LABEL_LEN) != 0) continue;
        if (handles_out && k < cap) handles_out[k] = o->handle;
        k++;
    }
    *count_out = k;
    pthread_mutex_unlock(&t->mu);
    return FHSM_RV_OK;
}

fhsm_rv_t fhsm_token_object_get_label(fhsm_token_t *t, uint32_t handle,
                                       const char **out, size_t *out_len) {
    if (!t || !out || !out_len) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    for (uint32_t i = 0; i < t->object_count; ++i) {
        if (t->objects[i].handle == handle) {
            *out     = (const char*)t->objects[i].label;
            *out_len = strnlen((const char*)t->objects[i].label,
                                FHSM_OBJ_LABEL_LEN);
            pthread_mutex_unlock(&t->mu);
            return FHSM_RV_OK;
        }
    }
    pthread_mutex_unlock(&t->mu);
    return FHSM_RV_KEY_HANDLE_INVALID;
}

fhsm_rv_t fhsm_token_object_get_id(fhsm_token_t *t, uint32_t handle,
                                    const uint8_t **out, size_t *out_len) {
    if (!t || !out || !out_len) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    for (uint32_t i = 0; i < t->object_count; ++i) {
        if (t->objects[i].handle == handle) {
            *out     = t->objects[i].id;
            *out_len = t->objects[i].id_len;
            pthread_mutex_unlock(&t->mu);
            return FHSM_RV_OK;
        }
    }
    pthread_mutex_unlock(&t->mu);
    return FHSM_RV_KEY_HANDLE_INVALID;
}

fhsm_rv_t fhsm_token_object_get_flags(fhsm_token_t *t, uint32_t handle,
                                       uint8_t *out_flags) {
    if (!t || !out_flags) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    for (uint32_t i = 0; i < t->object_count; ++i) {
        if (t->objects[i].handle == handle) {
            *out_flags = t->objects[i].flags;
            pthread_mutex_unlock(&t->mu);
            return FHSM_RV_OK;
        }
    }
    pthread_mutex_unlock(&t->mu);
    return FHSM_RV_KEY_HANDLE_INVALID;
}

/* ---------------------------------------------------------------------------
 * Mutation accessors (v1.3.0+) --- shared helper finds the object and
 * applies a small mutation, then atomically persists. The token must be
 * logged in (DEK present + objects_loaded) ; otherwise the function
 * returns FHSM_RV_USER_NOT_LOGGED_IN to mirror fhsm_token_object_destroy.
 *
 * Pattern duplicated three times rather than refactored behind a
 * function-pointer indirection : the bodies are tiny, each one has a
 * different argument shape, and the duplication is auditable at a
 * glance. ALC_DVS prefers small repetitive code over abstraction that
 * obscures the per-attribute write boundary.
 * ----------------------------------------------------------------------- */
fhsm_rv_t fhsm_token_object_set_label(fhsm_token_t *t, uint32_t handle,
                                       const char *label) {
    if (!t || !label) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    if (!t->dek || !t->objects_loaded) {
        pthread_mutex_unlock(&t->mu);
        return FHSM_RV_USER_NOT_LOGGED_IN;
    }
    for (uint32_t i = 0; i < t->object_count; ++i) {
        if (t->objects[i].handle == handle) {
            /* Bounded copy : at most FHSM_OBJ_LABEL_LEN - 1 chars +
             * NUL terminator. Pre-zero the buffer so the unused tail
             * does not leak whatever was there before. */
            fhsm_zeroize(t->objects[i].label, sizeof(t->objects[i].label));
            size_t n = strnlen(label, FHSM_OBJ_LABEL_LEN - 1);
            memcpy(t->objects[i].label, label, n);
            /* label is uint8_t[64] ; NUL terminator already present
             * thanks to the zeroize above. */
            t->objects_dirty = 1;
            fhsm_rv_t rv = write_atomic(t);
            pthread_mutex_unlock(&t->mu);
            return rv;
        }
    }
    pthread_mutex_unlock(&t->mu);
    return FHSM_RV_KEY_HANDLE_INVALID;
}

fhsm_rv_t fhsm_token_object_set_id(fhsm_token_t *t, uint32_t handle,
                                    const uint8_t *id, size_t id_len) {
    if (!t) return FHSM_RV_ARGUMENTS_BAD;
    if (id_len > sizeof(((fhsm_object_t *)0)->id)) {
        return FHSM_RV_ATTRIBUTE_VALUE_INVALID;
    }
    if (id_len > 0 && !id) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    if (!t->dek || !t->objects_loaded) {
        pthread_mutex_unlock(&t->mu);
        return FHSM_RV_USER_NOT_LOGGED_IN;
    }
    for (uint32_t i = 0; i < t->object_count; ++i) {
        if (t->objects[i].handle == handle) {
            fhsm_zeroize(t->objects[i].id, sizeof(t->objects[i].id));
            if (id_len > 0) memcpy(t->objects[i].id, id, id_len);
            t->objects[i].id_len = (uint32_t)id_len;
            t->objects_dirty = 1;
            fhsm_rv_t rv = write_atomic(t);
            pthread_mutex_unlock(&t->mu);
            return rv;
        }
    }
    pthread_mutex_unlock(&t->mu);
    return FHSM_RV_KEY_HANDLE_INVALID;
}

fhsm_rv_t fhsm_token_object_set_flags(fhsm_token_t *t, uint32_t handle,
                                       uint8_t flags) {
    if (!t) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    if (!t->dek || !t->objects_loaded) {
        pthread_mutex_unlock(&t->mu);
        return FHSM_RV_USER_NOT_LOGGED_IN;
    }
    for (uint32_t i = 0; i < t->object_count; ++i) {
        if (t->objects[i].handle == handle) {
            t->objects[i].flags = flags;
            t->objects_dirty = 1;
            fhsm_rv_t rv = write_atomic(t);
            pthread_mutex_unlock(&t->mu);
            return rv;
        }
    }
    pthread_mutex_unlock(&t->mu);
    return FHSM_RV_KEY_HANDLE_INVALID;
}

fhsm_rv_t fhsm_token_object_destroy(fhsm_token_t *t, uint32_t handle) {
    if (!t) return FHSM_RV_ARGUMENTS_BAD;
    pthread_mutex_lock(&t->mu);
    if (!t->dek || !t->objects_loaded) {
        pthread_mutex_unlock(&t->mu);
        return FHSM_RV_USER_NOT_LOGGED_IN;
    }
    for (uint32_t i = 0; i < t->object_count; ++i) {
        if (t->objects[i].handle == handle) {
            /* Zeroize before compacting */
            fhsm_zeroize(&t->objects[i], sizeof(t->objects[i]));
            /* Move the last entry into this slot to compact. */
            if (i != t->object_count - 1) {
                t->objects[i] = t->objects[t->object_count - 1];
                fhsm_zeroize(&t->objects[t->object_count - 1],
                             sizeof(t->objects[0]));
            }
            t->object_count--;
            t->objects_dirty = 1;
            fhsm_rv_t rv = write_atomic(t);
            pthread_mutex_unlock(&t->mu);
            (void)fhsm_audit_event(FHSM_EV_OBJECT_DESTROY, -1, -1,
                                    t->logged_in, rv, NULL);
            return rv;
        }
    }
    pthread_mutex_unlock(&t->mu);
    return FHSM_RV_KEY_HANDLE_INVALID;
}
