#include <stdarg.h>
#include <common/log.h>
#include "torsocks.h"

#if (defined(__FreeBSD__) || defined(__darwin__) || defined(__NetBSD__))
/* kqueue(2) */
TSOCKS_LIBC_DECL(kqueue, LIBC_KQUEUE_RET_TYPE, LIBC_KQUEUE_SIG)
#if defined(__NetBSD__)
/* kqueue1(2) */
TSOCKS_LIBC_DECL(kqueue1, LIBC_KQUEUE1_RET_TYPE, LIBC_KQUEUE1_SIG)
#endif
/*
 * Torsocks call for kqueue(2).
 */
LIBC_KQUEUE_RET_TYPE tsocks_kqueue(LIBC_KQUEUE_SIG)
{
	int fd;

	DBG("[kqueue] kqueue caught with size '%d'", size);

	fd = tsocks_libc_kqueue(LIBC_KQUEUE_ARGS);
	if (fd == -1) {
		DBG("[kqueue] kqueue failed. '%s'", strerror(errno));
	} else {
		DBG("[kqueue] kqueue returned fd %d", fd);
	}
	return fd;
}

#if defined(__NetBSD__)
/*
 * Torsocks call for kqueue1(2).
 */
LIBC_KQUEUE_RET_TYPE tsocks_kqueue1(LIBC_KQUEUE1_SIG)
{
	int fd;

	DBG("[kqueue1] kqueue1 caught with flags '%d'", flags);

	fd = tsocks_libc_kqueue1(LIBC_KQUEUE1_ARGS);
	if (fd == -1) {
		DBG("[kqueue1] kqueue1 failed. '%s'", strerror(errno));
	} else {
		DBG("[kqueue1] kqueue1 returned fd %d", fd);
	}
	return fd;
}
#endif

/*
 * Libc hijacked symbol kqueue(2).
 */
LIBC_KQUEUE_DECL
{
	if (!tsocks_libc_kqueue) {
		tsocks_libc_kqueue = tsocks_find_libc_symbol(
				LIBC_KQUEUE_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_kqueue(LIBC_KQUEUE_ARGS);
}

#if defined(__NetBSD__)
/*
 * Libc hijacked symbol kqueue1(2).
 */
LIBC_KQUEUE1_DECL
{
	if (!tsocks_libc_kqueue1) {
		tsocks_libc_kqueue1 = tsocks_find_libc_symbol(
				LIBC_KQUEUE1_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_kqueue1(LIBC_KQUEUE1_ARGS);
}
#endif /* NetBSD */
#endif /* __FreeBSD__, __darwin__, __NetBSD__ */
