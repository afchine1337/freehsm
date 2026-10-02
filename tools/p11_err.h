/* ===========================================================================
 * Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
 * SPDX-License-Identifier: Apache-2.0
 * ===========================================================================
 * tools/p11_err.h --- an error that is returned rather than printed.
 *
 *  Shared by tools/p11_util.h and tools/pkiops.h. It lives on its own because
 *  pkiops.h must not include p11_util.h: that header declares the module's
 *  function table `static`, so every file including it gets its own copy, and
 *  a table loaded in one file is empty in the next. pkiops.c is the one file
 *  that includes p11_util.h; everything else sees this struct and nothing more.
 *
 *  `code` is the exit status a command-line tool would use: 2 for the module or
 *  a PKCS#11 call, 3 for a slot or a key that is missing or ambiguous. `msg` is
 *  the whole message without the tool's name, final newline included, and may
 *  run over several lines.
 * ========================================================================= */
#ifndef FHSM_TOOLS_P11_ERR_H
#define FHSM_TOOLS_P11_ERR_H

struct p11_err { int code; char msg[4096]; };

#endif /* FHSM_TOOLS_P11_ERR_H */
