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

#include <common/connection.h>
#include <common/log.h>

#include "torsocks.h"

/* shutdown(2) */
TSOCKS_LIBC_DECL(shutdown, LIBC_SHUTDOWN_RET_TYPE, LIBC_SHUTDOWN_SIG)

/*
 * Torsocks call for shutdown(2).
 */
LIBC_SHUTDOWN_RET_TYPE tsocks_shutdown(LIBC_SHUTDOWN_SIG)
{
	struct connection *conn;

	DBG("Shutdown catched for fd %d", sockfd);

	connection_registry_lock();
	conn = connection_find(sockfd);
	if (conn) {
		int tsocks_fd = conn->tsocks_fd;
		/*
		 * Remove from the registry so it's not visible anymore and thus using
		 * it without lock.
		 */
		connection_remove(conn);
		/*
		 * Put back the connection reference. If the refcount get to 0, the
		 * connection pointer is destroyed.
		 */
		DBG("Shutdown connection putting back ref");
		connection_put_ref(conn);
		return tsocks_libc_shutdown(tsocks_fd, how);
	}
	connection_registry_unlock();

	/* Return the original libc close. */
	return tsocks_libc_shutdown(sockfd, how);
}

/*
 * Libc hijacked symbol shutdown(2).
 */
LIBC_SHUTDOWN_DECL
{
	if (!tsocks_libc_shutdown) {
		tsocks_libc_shutdown = tsocks_find_libc_symbol(
				LIBC_SHUTDOWN_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_shutdown(LIBC_SHUTDOWN_ARGS);
}
