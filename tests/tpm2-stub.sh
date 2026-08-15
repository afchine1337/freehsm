#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
#
# A stand-in for the tpm2-tools CLI, for machines with no TPM.
#
# WHAT THIS IS NOT
# ----------------
# It is not a TPM simulator and it performs no cryptography. It cannot tell
# you anything about PCR binding, the sealing algorithms, or tamper detection
# -- those live inside the TPM, and here there is no TPM. Do not read a green
# run of test_tpm as evidence that TPM sealing works.
#
# WHAT IT IS FOR
# --------------
# fhsm_tpm.c drives tpm2 by building command lines and passing file paths.
# Everything that can go wrong on our side of that boundary -- which paths we
# hand over, whether we pack and unpack the blob correctly, what we do when a
# command fails -- is testable without a TPM, and was previously untested.
# In particular it lets us assert the #109 property directly: every path this
# script is handed must be under /proc/self/fd/, i.e. an anonymous in-memory
# file, never a filesystem.
#
# Knobs, all via environment:
#   FHSM_TPM_FAKE_LOG    append every argument list here (path assertions)
#   FHSM_TPM_FAKE_PCR    stands in for current PCR state; changing it between
#                        seal and unseal simulates a firmware/kernel update
#   FHSM_TPM_FAKE_FAIL   if set to a subcommand name, that subcommand exits 1

log_args() {
    [ -n "$FHSM_TPM_FAKE_LOG" ] && echo "$*" >> "$FHSM_TPM_FAKE_LOG"
    return 0
}

# Pull the argument following a flag out of the remaining command line.
flag_val() {
    _want=$1; shift
    while [ $# -gt 0 ]; do
        if [ "$1" = "$_want" ]; then echo "$2"; return 0; fi
        shift
    done
    return 0
}

sub=$1; shift
log_args "$sub $*"

if [ -n "$FHSM_TPM_FAKE_FAIL" ] && [ "$FHSM_TPM_FAKE_FAIL" = "$sub" ]; then
    exit 1
fi

pcr=${FHSM_TPM_FAKE_PCR:-default-pcr-state}

case "$sub" in
    startup)
        exit 0
        ;;

    createpolicy)
        # -L <out> receives the policy digest. Ours is just the PCR string,
        # which is enough to make "the PCRs moved" observable.
        out=$(flag_val -L "$@")
        [ -n "$out" ] || exit 1
        printf 'POLICY:%s' "$pcr" > "$out"
        exit 0
        ;;

    create)
        # -i <secret in>  -u <pub out>  -r <priv out>  -L <policy in>
        in=$(flag_val -i "$@")
        pub=$(flag_val -u "$@")
        priv=$(flag_val -r "$@")
        pol=$(flag_val -L "$@")
        [ -n "$in" ] && [ -n "$pub" ] && [ -n "$priv" ] && [ -n "$pol" ] || exit 1
        # "pub" carries the policy the object was sealed under; "priv" carries
        # the secret verbatim. Verbatim, not encoded: a DEK is 32 arbitrary
        # bytes including NULs, and every shell mechanism for moving those
        # around through a variable eats them. A real TPM would encrypt this;
        # this one does not, which is precisely why the stub must never leave
        # the test directory.
        cat "$pol" > "$pub"
        cat "$in"  > "$priv"
        exit 0
        ;;

    load)
        # -u <pub> -r <priv> -c <ctx out>: our context is just the two joined.
        pub=$(flag_val -u "$@")
        priv=$(flag_val -r "$@")
        ctx=$(flag_val -c "$@")
        [ -n "$pub" ] && [ -n "$priv" ] && [ -n "$ctx" ] || exit 1
        # Policy on the first line, then the sealed bytes verbatim. The
        # policy never contains a newline, so `head -n1` recovers it exactly
        # and `tail -c 32` recovers the DEK regardless of its contents.
        { cat "$pub"; printf '\n'; cat "$priv"; } > "$ctx"
        exit 0
        ;;

    unseal)
        # -c <ctx> -o <out>. Release the secret only if the policy recorded at
        # seal time still matches the current PCR state -- the one behaviour of
        # a real TPM we do need to imitate, because it is what turns a firmware
        # update into a failed unseal.
        ctx=$(flag_val -c "$@")
        out=$(flag_val -o "$@")
        [ -n "$ctx" ] && [ -n "$out" ] || exit 1
        sealed_pol=$(head -n1 "$ctx")
        [ "$sealed_pol" = "POLICY:$pcr" ] || exit 1
        tail -c 32 "$ctx" > "$out"
        exit 0
        ;;

    *)
        exit 1
        ;;
esac
