#include <stdarg.h>
#include <common/log.h>
#include "torsocks.h"

/* open(2) */
TSOCKS_LIBC_DECL(open, LIBC_OPEN_RET_TYPE, LIBC_OPEN_SIG)
/*
 * Torsocks call for open(2).
 */
LIBC_OPEN_RET_TYPE tsocks_open(LIBC_OPEN_SIG)
{
	int fd;
	va_list mode;

	DBG("[open] Open caught on file '%s'", file);
	va_start(mode, oflag);
        
	fd = tsocks_libc_open(LIBC_OPEN_ARGS);
	if (fd == -1) {
		DBG("[open] Open failed. '%s'", strerror(errno));
	} else {
		DBG("[open] Open returned fd %d", fd);
	}
	return fd;
}

/*
 * Libc hijacked symbol open(2).
 */
LIBC_OPEN_DECL
{
	va_list mode;
	va_start(mode, oflag);

	if (!tsocks_libc_open) {
		tsocks_libc_open = tsocks_find_libc_symbol(
				LIBC_OPEN_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_open(LIBC_OPEN_ARGS);
}
