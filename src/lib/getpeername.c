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

#include <arpa/inet.h>
#include <assert.h>

#include <common/log.h>

#include "torsocks.h"

/* getpeername(2) */
TSOCKS_LIBC_DECL(getpeername, LIBC_GETPEERNAME_RET_TYPE,
		LIBC_GETPEERNAME_SIG)

/*
 * Torsocks call for getpeername(2).
 */
LIBC_GETPEERNAME_RET_TYPE tsocks_getpeername(LIBC_GETPEERNAME_SIG)
{
	int ret = 0;
	struct connection *conn;
	socklen_t sz = 0;
	char dotted[128];

	DBG("[getpeername] Requesting address on socket %d", sockfd);

	connection_registry_lock();
	conn = connection_find(sockfd);
	if (!conn) {
		connection_registry_unlock();
		DBG("Connection not in table. Jumping to libc resolution.");
		goto libc;
	}
	DBG("Found connection in table. Resolving internally.");

	if (!addrlen || !addr) {
		/* Bad address. */
		DBG("addrlen (%#x) or addr (%#x) invalid", addrlen, addr);
		errno = EFAULT;
		ret = -1;
		goto end;
	}

	/*
	 * Extra check for addrlen since we are about to copy the connection
	 * content into the given address.
	 */
	if (*addrlen > sizeof(struct sockaddr)) {
		/* Ref to the manpage for the returned value here. */
		DBG("addrlen (%#x) invalid (%d)", addrlen, *addrlen);
		errno = EINVAL;
		ret = -1;
		goto end;
	}

	/*
	 * Copy the minimum of *addrlen and the size of the actual address
	 * into the given addr. There are applications that pass in buffers
	 * that are rather large, which is acceptable behavior.
	 */
	switch (conn->dest_addr.domain) {
	case CONNECTION_DOMAIN_NAME:
		/*
		 * This domain is only used with onion address which contains a
		 * cookie address of domain INET. Use that since that's the address
		 * that has been returned to the application.
		 */
	case CONNECTION_DOMAIN_INET:
		sz = min(sizeof(conn->dest_addr.u.sin), *addrlen);
		memcpy(addr, (const struct sockaddr *) &conn->dest_addr.u.sin,
				sz);
		inet_ntop(conn->dest_addr.u.sin.sin_family, &conn->dest_addr.u.sin.sin_addr,
			  dotted, 128);
		DBG("Returning peername of INET addr %#x (%s)",
		    conn->dest_addr.u.sin.sin_addr.s_addr, dotted);
		break;
	case CONNECTION_DOMAIN_INET6:
		sz = min(sizeof(conn->dest_addr.u.sin6), *addrlen);
		memcpy(addr, (const struct sockaddr *) &conn->dest_addr.u.sin6,
				sz);
		inet_ntop(conn->dest_addr.u.sin6.sin6_family, &conn->dest_addr.u.sin6.sin6_addr,
			  dotted, 128);
		DBG("Returning peername of INET6 addr %#x (%s)",
		    conn->dest_addr.u.sin6.sin6_addr.s6_addr, dotted);
		break;
	case CONNECTION_DOMAIN_NOT_KNOWN:
	case CONNECTION_DOMAIN_UNIX:
		ERR("Destination socket unsupported type");
		errno = EINVAL;
		ret = -1;
		goto end;
	}

	/* Success. */
	*addrlen = sz;
	errno = 0;
	ret = 0;

end:
	connection_registry_unlock();
	return ret;

libc:
	/*
	 * This is clearly not a socket we are handling so it's safe to pass it to
	 * the original libc call.
	 */
	return tsocks_libc_getpeername(LIBC_GETPEERNAME_ARGS);
}

/*
 * Libc hijacked symbol getpeername(2).
 */
LIBC_GETPEERNAME_DECL
{
	if (!tsocks_libc_getpeername) {
		tsocks_initialize();
		tsocks_libc_getpeername = tsocks_find_libc_symbol(
				LIBC_GETPEERNAME_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_getpeername(LIBC_GETPEERNAME_ARGS);
}
