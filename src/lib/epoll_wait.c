#include <stdarg.h>
#include <common/log.h>
#include "torsocks.h"
#include <common/connection.h>

/* epoll_wait(2) */
TSOCKS_LIBC_DECL(epoll_wait, LIBC_EPOLL_WAIT_RET_TYPE, LIBC_EPOLL_WAIT_SIG)

/* epoll_pwait(2) */
TSOCKS_LIBC_DECL(epoll_pwait, LIBC_EPOLL_PWAIT_RET_TYPE, LIBC_EPOLL_PWAIT_SIG)

/*
 * Torsocks call for epoll_wait(2).
 */
LIBC_EPOLL_WAIT_RET_TYPE tsocks_epoll_wait(LIBC_EPOLL_WAIT_SIG)
{
	int nfd;

	DBG("[epoll_wait] epoll_wait caught, epfd '%d', max events %d, timeout %d",
	    epfd, maxevents, timeout);

	nfd = tsocks_libc_epoll_wait(LIBC_EPOLL_WAIT_ARGS);
	DBG("[epoll_wait] epoll_wait returned %d%s%s", nfd, nfd == -1 ? " " : "",
	    nfd == -1 ? strerror(errno) : "");
	return nfd;
}

/*
 * Torsocks call for epoll_pwait(2).
 */
LIBC_EPOLL_PWAIT_RET_TYPE tsocks_epoll_pwait(LIBC_EPOLL_PWAIT_SIG)
{
	int nfd;

	DBG("[epoll_pwait] epoll_pwait caught, epfd '%d', max events %d, "
	    "timeout %d, sigmask %x", epfd, maxevents, timeout, sigmask);

	nfd = tsocks_libc_epoll_pwait(LIBC_EPOLL_PWAIT_ARGS);
	DBG("[epoll_pwait] epoll_pwait returned %d%s%s", nfd, nfd == -1 ? " " : "",
	    nfd == -1 ? strerror(errno) : "");
	return nfd;
}

/*
 * Libc hijacked symbol epoll_wait(2).
 */
LIBC_EPOLL_WAIT_DECL
{
	if (!tsocks_libc_epoll_wait) {
		tsocks_libc_epoll_wait = tsocks_find_libc_symbol(
				LIBC_EPOLL_WAIT_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_epoll_wait(LIBC_EPOLL_WAIT_ARGS);
}

/*
 * Libc hijacked symbol epoll_pwait(2).
 */
LIBC_EPOLL_PWAIT_DECL
{
	if (!tsocks_libc_epoll_pwait) {
		tsocks_libc_epoll_pwait = tsocks_find_libc_symbol(
				LIBC_EPOLL_PWAIT_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_epoll_pwait(LIBC_EPOLL_PWAIT_ARGS);
}
