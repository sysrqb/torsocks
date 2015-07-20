/*
 * Copyright (C) 2013 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include <common/connection.h>
#include <common/log.h>
#include <common/utils.h>

#include "torsocks.h"

/* dup(2) */
TSOCKS_LIBC_DECL(dup, LIBC_DUP_RET_TYPE, LIBC_DUP_SIG)
/* dup2(2) */
TSOCKS_LIBC_DECL(dup2, LIBC_DUP2_RET_TYPE, LIBC_DUP2_SIG)
#if (defined(__linux__))
/* dup3(2) */
TSOCKS_LIBC_DECL(dup3, LIBC_DUP3_RET_TYPE, LIBC_DUP3_SIG)
#endif /* __linux__ */


/*
 * Torsocks call for dup(2)
 *
 * We hijack this call so we can splice together the app<->torsocks
 * and torsocks<->op connections.
 */
LIBC_DUP_RET_TYPE tsocks_dup(LIBC_DUP_SIG)
{
	DBG("[dup] Dup caught on fd %d", oldfd);
	return tsocks_libc_dup(LIBC_DUP_ARGS);
}

/*
 * Torsocks call for dup2(2)
 *
 * We hijack this call so we can splice together the app<->torsocks
 * and torsocks<->op connections.
 */
LIBC_DUP2_RET_TYPE tsocks_dup2(LIBC_DUP2_SIG)
{
	DBG("[dup2] Dup caught on fd %d, new fd %d", oldfd, newfd);
	return tsocks_libc_dup2(LIBC_DUP2_ARGS);
}

/*
 * Torsocks call for dup3(2)
 *
 * We hijack this call so we can splice together the app<->torsocks
 * and torsocks<->op connections.
 */
LIBC_DUP3_RET_TYPE tsocks_dup3(LIBC_DUP3_SIG)
{
	DBG("[dup3] Dup caught on fd %d, new fd %d", oldfd, newfd);
	return tsocks_libc_dup3(LIBC_DUP3_ARGS);
}

/*
 * Libc hijacked symbol dup(2).
 */
LIBC_DUP_DECL
{
	if (!tsocks_libc_dup) {
		tsocks_libc_dup = tsocks_find_libc_symbol(
				LIBC_DUP_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_dup(LIBC_DUP_ARGS);
}

/*
 * Libc hijacked symbol dup2(2).
 */
LIBC_DUP_DECL
{
	if (!tsocks_libc_dup2) {
		tsocks_libc_dup2 = tsocks_find_libc_symbol(
				LIBC_DUP2_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_dup2(LIBC_DUP2_ARGS);
}

/*
 * Libc hijacked symbol dup3(2).
 */
LIBC_DUP_DECL
{
	if (!tsocks_libc_dup3) {
		tsocks_libc_dup3 = tsocks_find_libc_symbol(
				LIBC_DUP3_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_dup3(LIBC_DUP3_ARGS);
}
