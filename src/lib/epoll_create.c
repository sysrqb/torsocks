#include <stdarg.h>
#include <common/log.h>
#include "torsocks.h"

#if (defined(__linux__))
/* epoll_create(2) */
TSOCKS_LIBC_DECL(epoll_create, LIBC_EPOLL_CREATE_RET_TYPE, LIBC_EPOLL_CREATE_SIG)
/* epoll_create1(2) */
TSOCKS_LIBC_DECL(epoll_create1, LIBC_EPOLL_CREATE1_RET_TYPE, LIBC_EPOLL_CREATE1_SIG)
/*
 * Torsocks call for epoll_create(2).
 */
LIBC_EPOLL_CREATE_RET_TYPE tsocks_epoll_create(LIBC_EPOLL_CREATE_SIG)
{
	int fd;

	DBG("[epoll_create] epoll_create caught with size '%d'", size);

	fd = tsocks_libc_epoll_create(LIBC_EPOLL_CREATE_ARGS);
	if (fd == -1) {
		DBG("[epoll_create] epoll_create failed. '%s'", strerror(errno));
	} else {
		DBG("[epoll_create] epoll_create returned fd %d", fd);
	}
	return fd;
}

/*
 * Torsocks call for epoll_create1(2).
 */
LIBC_EPOLL_CREATE_RET_TYPE tsocks_epoll_create1(LIBC_EPOLL_CREATE1_SIG)
{
	int fd;

	DBG("[epoll_create1] epoll_create1 caught with flags '%d'", flags);

	fd = tsocks_libc_epoll_create1(LIBC_EPOLL_CREATE1_ARGS);
	if (fd == -1) {
		DBG("[epoll_create1] epoll_create1 failed. '%s'", strerror(errno));
	} else {
		DBG("[epoll_create1] epoll_create1 returned fd %d", fd);
	}
	return fd;
}

/*
 * Libc hijacked symbol epoll_create(2).
 */
LIBC_EPOLL_CREATE_DECL
{
	if (!tsocks_libc_epoll_create) {
		tsocks_libc_epoll_create = tsocks_find_libc_symbol(
				LIBC_EPOLL_CREATE_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_epoll_create(LIBC_EPOLL_CREATE_ARGS);
}

/*
 * Libc hijacked symbol epoll_create1(2).
 */
LIBC_EPOLL_CREATE1_DECL
{
	if (!tsocks_libc_epoll_create1) {
		tsocks_libc_epoll_create1 = tsocks_find_libc_symbol(
				LIBC_EPOLL_CREATE1_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_epoll_create1(LIBC_EPOLL_CREATE1_ARGS);
}
#endif /* __linux__ */
