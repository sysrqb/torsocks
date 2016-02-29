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

/* writev(2) */
TSOCKS_LIBC_DECL(writev, LIBC_WRITEV_RET_TYPE, LIBC_WRITEV_SIG)


/*
 * Torsocks call for writev(2)
 *
 * We hijack this call so we can splice together the app<->torsocks
 * and torsocks<->op connections.
 */
LIBC_WRITEV_RET_TYPE tsocks_writev(LIBC_WRITEV_SIG)
{
	struct connection *conn;

	conn = connection_find(fd);
	if (conn)
		fd = conn->tor_fd;
	return tsocks_libc_writev(LIBC_WRITEV_ARGS);
}

/*
 * Libc hijacked symbol writev(2).
 */
LIBC_WRITEV_DECL
{
	if (!tsocks_libc_writev) {
		tsocks_libc_writev = tsocks_find_libc_symbol(
				LIBC_WRITEV_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_writev(LIBC_WRITEV_ARGS);
}
