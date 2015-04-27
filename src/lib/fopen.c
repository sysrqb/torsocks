#include <stdio.h>
#include <common/log.h>
#include "torsocks.h"

/* fopen(3) */
TSOCKS_LIBC_DECL(fopen, LIBC_FOPEN_RET_TYPE, LIBC_FOPEN_SIG)
/* fdopen(3) */
TSOCKS_LIBC_DECL(fdopen, LIBC_FDOPEN_RET_TYPE, LIBC_FDOPEN_SIG)
/* freopen(3) */
TSOCKS_LIBC_DECL(freopen, LIBC_FREOPEN_RET_TYPE, LIBC_FREOPEN_SIG)

/*
 * Torsocks call for fopen(3).
 */
LIBC_FOPEN_RET_TYPE tsocks_fopen(LIBC_FOPEN_SIG)
{
	FILE *file;
	int fd;

	DBG("[fopen] Open caught on file '%s'", path);
	file = tsocks_libc_fopen(LIBC_FOPEN_ARGS);
	if (file != NULL) {
		fd = fileno(file);
		DBG("[fopen] libc returned FILE stream %#x, fd %d", file, fd);
	} else {
		DBG("[fopen] libc returned NULL, %s", strerror(errno));
	}
	return file;
}

/*
 * Torsocks call for fdopen(3).
 */
LIBC_FDOPEN_RET_TYPE tor_fdopen(LIBC_FDOPEN_SIG)
{
	FILE *file;
	DBG("[fdopen] Open caught for fd %d, '%s'", fd, mode);

	file = tsocks_libc_fdopen(LIBC_FDOPEN_ARGS);
	if (file != NULL) {
		DBG("[fdopen] libc returned FILE stream %#x", file);
	} else {
		DBG("[fdopen] libc returned NULL, %s", strerror(errno));
	}
	return file;
}
/*
 * Torsocks call for freopen(3).
 */
LIBC_FREOPEN_RET_TYPE tsocks_freopen(LIBC_FREOPEN_SIG)
{
	FILE *file;
	int fd;

	DBG("[freopen] Reopen caught on file '%s', reopening on %x",
	    path, stream);

	file = tsocks_libc_freopen(LIBC_FREOPEN_ARGS);
	if (file != NULL) {
		fd = fileno(file);
		DBG("[freopen] libc returned FILE stream %#x, fd %d", file, fd);
	} else {
		DBG("[freopen] libc returned NULL, %s", strerror(errno));
	}
	return file;
}

/*
 * Libc hijacked symbol fopen(3).
 */
LIBC_FOPEN_DECL
{
	if (!tsocks_libc_fopen) {
		tsocks_libc_fopen = tsocks_find_libc_symbol(
				LIBC_FOPEN_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_fopen(LIBC_FOPEN_ARGS);
}

/*
 * Libc hijacked symbol fdopen(3).
 */
LIBC_FDOPEN_DECL
{
	if (!tsocks_libc_fdopen) {
		tsocks_libc_fdopen = tsocks_find_libc_symbol(
				LIBC_FDOPEN_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tor_fdopen(LIBC_FDOPEN_ARGS);
}

/*
 * Libc hijacked symbol freopen(3).
 */
LIBC_FREOPEN_DECL
{
	if (!tsocks_libc_freopen) {
		tsocks_libc_freopen = tsocks_find_libc_symbol(
				LIBC_FREOPEN_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_freopen(LIBC_FREOPEN_ARGS);
}
