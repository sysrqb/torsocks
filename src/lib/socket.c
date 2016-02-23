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

#include <common/log.h>

#include "torsocks.h"

/* socket(2) */
TSOCKS_LIBC_DECL(socket, LIBC_SOCKET_RET_TYPE, LIBC_SOCKET_SIG)

#define CASE_DOMAIN(d)		\
	case d:			\
		name = #d;	\
		break

#define SOCKET_TYPE(t)					\
	if ((type & t) == 0) {				\
		name = #t;				\
	} else if ((type & (t | SOCK_NONBLOCK)) == 0) {	\
		name = #t " | SOCK_NONBLOCK";		\
	} else if ((type & (t | SOCK_CLOEXEC)) == 0) {	\
		name = #t " | SOCK_CLOEXEC";		\
	}

static
char * domain_str(int domain, char *buf, size_t buflen)
{
	char *name;
	switch (domain) {
	CASE_DOMAIN(AF_UNIX|AF_LOCAL);
	CASE_DOMAIN(AF_INET);
	CASE_DOMAIN(AF_INET6);
	CASE_DOMAIN(AF_IPX);
	CASE_DOMAIN(AF_APPLETALK);
#if defined(__linux__)
	CASE_DOMAIN(AF_NETLINK);
	CASE_DOMAIN(AF_X25);
	CASE_DOMAIN(AF_AX25);
	CASE_DOMAIN(AF_ATMPVC);
	CASE_DOMAIN(AF_PACKET);
#endif
	default:
		name = "AF not recognized";
	}

	buflen = buflen > strlen(name)?strlen(name):buflen;
	strncpy(buf, name, buflen);
	return buf;
}

static
char * type_str(int type, char *buf, size_t buflen)
{
	char *name = "AF not recognized";
	SOCKET_TYPE(SOCK_STREAM)
	else SOCKET_TYPE(SOCK_DGRAM)
	else SOCKET_TYPE(SOCK_SEQPACKET)
	else SOCKET_TYPE(SOCK_RAW)
	else SOCKET_TYPE(SOCK_RDM)
#if defined(__linux__)
	else SOCKET_TYPE(SOCK_PACKET)
#endif

	buflen = buflen > strlen(name)?strlen(name):buflen;
	strncpy(buf, name, buflen);
	return buf;
}

static
char * proto_str(int protocol, char *buf, size_t buflen)
{
	char *name;
	struct protoent *ent;

	ent = getprotobynumber(protocol);
	if (ent == NULL)
		name = "protocol not recognized";
	else
		name = ent->p_name;
	endprotoent();

	buflen = buflen > strlen(name)?strlen(name):buflen;
	strncpy(buf, name, buflen);
	return buf;
}
/*
 * Torsocks call for socket(2)
 */
LIBC_SOCKET_RET_TYPE tsocks_socket(LIBC_SOCKET_SIG)
{
	int fd;
	char descr_buf1[20];
	char descr_buf2[20];
	char descr_buf3[20];

	/* Only do this if the debug message is printed. */
	if (tsocks_loglevel >= MSGDEBUG) {
		memset(descr_buf1, 0, sizeof(descr_buf1));
		memset(descr_buf2, 0, sizeof(descr_buf2));
		memset(descr_buf3, 0, sizeof(descr_buf3));
	}

	DBG("[socket] Creating socket with domain %s (%d), type %s (%d) and "
		"protocol %s (%d)",
			domain_str(domain, descr_buf1, sizeof(descr_buf1)),
			domain, type_str(type, descr_buf2, sizeof(descr_buf2)),
			type, proto_str(protocol, descr_buf3, sizeof(descr_buf3)),
			protocol);

	if (IS_SOCK_STREAM(type)) {
		/*
		 * The socket family is not checked here since we accept local socket
		 * (AF_UNIX) that can NOT do outbound traffic.
		 */
		goto end;
	} else {
		/*
		 * Non INET[6] socket can't be handle by tor else create the socket.
		 * The connect function will deny anything that Tor can NOT handle.
		 */
		if (domain != AF_INET && domain != AF_INET6) {
			goto end;
		}

		/*
		 * Print this message only in debug mode. Very often, applications uses
		 * the libc to do DNS resolution which first tries with UDP and then
		 * with TCP. It's not critical for the user to know that a non TCP
		 * socket has been denied and since the libc has a fallback that works,
		 * this message most of the time, simply polutes the application's
		 * output which can cause issues with external applications parsing the
		 * output.
		 */
		DBG("IPv4/v6 non TCP socket denied. Tor network can't handle it.");
		errno = EACCES;
		return -1;

	}

end:
	/* Stream socket for INET/INET6 is good so open it. */
	fd = tsocks_libc_socket(domain, type, protocol);
	DBG("[socket] Created socket fd %d", fd);
	return fd;
}

/*
 * Libc hijacked symbol socket(2).
 */
LIBC_SOCKET_DECL
{
	if (!tsocks_libc_socket)
		tsocks_initialize();
	return tsocks_socket(LIBC_SOCKET_ARGS);
}
