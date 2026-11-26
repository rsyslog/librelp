/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Optional multi-digest GnuTLS fingerprint verification.
 *
 * Copyright 2008-2025 by Rainer Gerhards and Adiscon GmbH.
 * Copyright 2018 briaeros <briaeros@users.noreply.github.com>
 * Copyright 2022 alakatos <alakatos@redhat.com>
 *
 * This internal unit preserves the GnuTLS digest selection and fingerprint
 * formatting contribution from librelp commit
 * d3b58a58aa5911b24645126d14b06b3f3af89c0f, including the formatter
 * terminator fix from commit 6704009c1fa7daa1997fa05297e9b99dd4e9f974.
 * Keep this optional unit separate from code selected for the Apache License
 * 2.0 profile.
 *
 * This file is part of librelp.
 *
 * Librelp is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Librelp is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with librelp. If not, see <https://www.gnu.org/licenses/>.
 *
 * A copy of the GPL can be found in the file "COPYING" in this distribution.
 *
 * If the terms of the GPL are unsuitable for your needs, you may obtain a
 * commercial license from Adiscon. Contact sales@adiscon.com for further
 * details.
 *
 * ALL CONTRIBUTORS PLEASE NOTE that by sending contributions, you assign
 * your copyright to Adiscon GmbH, Germany. This is necessary to permit the
 * dual-licensing set forth here. Our apologies for this inconvenience, but
 * we sincerely believe that the dual-licensing model helps us provide great
 * free software while at the same time obtaining some funding for further
 * development.
 */

#ifndef RELP_GNUTLSFINGERPRINT_H_INCLUDED
#define RELP_GNUTLSFINGERPRINT_H_INCLUDED

#include <stddef.h>
#include <gnutls/x509.h>

#include "tcp.h"

typedef enum {
	relpGnuTlsFingerprintMatch,
	relpGnuTlsFingerprintNoMatch,
	relpGnuTlsFingerprintDigestError
} relpGnuTlsFingerprintResult_t;

relpGnuTlsFingerprintResult_t relpGnuTlsFingerprintCheck(
	gnutls_x509_crt_t cert, tcpPermittedPeers_t *listPeers,
	relpEngine_t *pEngine, char *fpPrintable, size_t fpPrintableSize,
	int *pGnuRet);

#endif /* RELP_GNUTLSFINGERPRINT_H_INCLUDED */
