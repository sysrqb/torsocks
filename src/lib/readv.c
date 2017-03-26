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

/* readv(2) */
TSOCKS_LIBC_DECL(readv, LIBC_READV_RET_TYPE, LIBC_READV_SIG)


/*
 * Torsocks call for readv(2)
 *
 * We hijack this call so we can splice together the app<->torsocks
 * and torsocks<->op connections.
 */
LIBC_READV_RET_TYPE tsocks_readv(LIBC_READV_SIG)
{
	struct connection *conn;

	conn = connection_find(fd);
	if (conn)
		fd = conn->tor_fd;
	return tsocks_libc_readv(LIBC_READV_ARGS);
}

/*
 * Libc hijacked symbol readv(2).
 */
LIBC_READV_DECL
{
	if (!tsocks_libc_readv) {
		tsocks_libc_readv = tsocks_find_libc_symbol(
				LIBC_READV_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_readv(LIBC_READV_ARGS);
}
