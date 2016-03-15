/*
 * Copyright (C) 2013 - David Goulet <dgoulet@ev0ke.net>
 * Copyright (C) 2015 - Tim Rühsen <tim.ruehsen@gmx.de>
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

#include <common/connection.h>
#include <common/log.h>
#include <common/utils.h>

#include "torsocks.h"

/* send(2) */
TSOCKS_LIBC_DECL(send, LIBC_SEND_RET_TYPE, LIBC_SEND_SIG)

/* sendto(2)
 * args: int sockfd, const void *buf, size_t len, int flags,
 *       const struct sockaddr *dest_addr, socklen_t addrlen
 */
TSOCKS_LIBC_DECL(sendto, LIBC_SENDTO_RET_TYPE, LIBC_SENDTO_SIG)


/* sendmsg(2) */
TSOCKS_LIBC_DECL(sendmsg, LIBC_SENDMSG_RET_TYPE, LIBC_SENDMSG_SIG)

/*
 * Torsocks call for send(2)
 *
 * We hijack this call so we can splice together the app<->torsocks
 * and torsocks<->op connections.
 */
LIBC_SEND_RET_TYPE tsocks_send(LIBC_SEND_SIG)
{
	struct connection *conn;

	conn = connection_find(sockfd);
	if (conn == NULL) {
		ERR("[send] Connection lookup failed for fd %d", sockfd);
		errno = EBADF;
		return -1;
	}
	sockfd = conn->tor_fd;
	return tsocks_libc_send(LIBC_SEND_ARGS);
}

/*
 * Using TCP Fast Open (TFO) uses sendto() instead of connect() with 'flags'
 * set to MSG_FASTOPEN. Without this code, using TFO simply bypasses Tor
 * without letting the user know.
 *
 * This solution simply ignores TFO and falls back to connect(). At the time
 * the tor server supports TFO, socks5.c (client code) could implement it in
 * send_data() and connect_socks5().
 */

/*
 * Torsocks call for sendto(2).
 */
LIBC_SENDTO_RET_TYPE tsocks_sendto(LIBC_SENDTO_SIG)
{
	int ret;
#ifdef MSG_FASTOPEN

	if ((flags & MSG_FASTOPEN) == 0) {
		/* No TFO, fallback to libc sendto() */
		goto libc_sendto;
	}

	DBG("[sendto] TCP fast open caught on fd %d", sockfd);

	ret = connect(sockfd, dest_addr, addrlen);
	if (ret == 0) {
		/* Connection established, send payload */
		ret = send(sockfd, buf, len, flags & ~MSG_FASTOPEN);
	}

	return ret;

libc_sendto:
#endif /* MSG_FASTOPEN */

	/* Validate that the socket and address are ok to send traffic to. */
	ret = tsocks_validate_socket(sockfd, dest_addr);
	if (ret == -1) {
		return ret;
	}

	return tsocks_libc_sendto(LIBC_SENDTO_ARGS);
}

/*
 * Torsocks call for sendmsg(2)
 *
 * We hijack this call so we can splice together the app<->torsocks
 * and torsocks<->op connections.
 */
LIBC_SENDMSG_RET_TYPE tsocks_sendmsg(LIBC_SENDMSG_SIG)
{
	struct connection *conn;

	conn = connection_find(sockfd);
	if (conn == NULL) {
		ERR("[sendmsg] Connection lookup failed for fd %d", sockfd);
		errno = EBADF;
		return -1;
	}
	sockfd = conn->tor_fd;
	return tsocks_libc_sendmsg(LIBC_SENDMSG_ARGS);
}

/*
 * Libc hijacked symbol send(2).
 */
LIBC_SEND_DECL
{
	if (!tsocks_libc_send) {
		tsocks_libc_send = tsocks_find_libc_symbol(
				LIBC_SEND_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_send(LIBC_SEND_ARGS);
}

/*
 * Libc hijacked symbol sendto(2).
 */
LIBC_SENDTO_DECL
{
	if (!tsocks_libc_sendto) {
		tsocks_libc_sendto = tsocks_find_libc_symbol(
				LIBC_SENDTO_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_sendto(LIBC_SENDTO_ARGS);
}

/*
 * Libc hijacked symbol sendmsg(2).
 */
LIBC_SENDMSG_DECL
{
	if (!tsocks_libc_sendmsg) {
		tsocks_initialize();
		/* Find symbol if not already set. Exit if not found. */
		tsocks_libc_sendmsg = tsocks_find_libc_symbol(LIBC_SENDMSG_NAME_STR,
				TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_sendmsg(LIBC_SENDMSG_ARGS);
}
