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

/* read(2) */
TSOCKS_LIBC_DECL(read, LIBC_READ_RET_TYPE, LIBC_READ_SIG)


/*
 * Torsocks call for read(2)
 *
 * We hijack this call so we can splice together the app<->torsocks
 * and torsocks<->op connections.
 */
LIBC_READ_RET_TYPE tsocks_read(LIBC_READ_SIG)
{
	struct connection *conn;

	DBG("[read] Read caught on fd %d", fd);
	conn = connection_find(fd);
	if (conn) {
		fd = conn->tsocks_fd;
		DBG("Found conn %#x with tsocks fd %d", conn, fd);
	}
	return tsocks_libc_read(LIBC_READ_ARGS);
}

/*
 * Libc hijacked symbol read(2).
 */
LIBC_READ_DECL
{
	if (!tsocks_libc_read) {
		tsocks_libc_read = tsocks_find_libc_symbol(
				LIBC_READ_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_read(LIBC_READ_ARGS);
}
