#include <stdarg.h>
#include <common/log.h>
#include "torsocks.h"
#include <stdlib.h>

/* poll(2) */
TSOCKS_LIBC_DECL(poll, LIBC_POLL_RET_TYPE, LIBC_POLL_SIG)
/* ppoll(2) */
TSOCKS_LIBC_DECL(ppoll, LIBC_PPOLL_RET_TYPE, LIBC_PPOLL_SIG)

/*
 * Replace tsocks fd with app fd
 *
 * *replaced* is a array of arrays. The arrays are of length two,
 * where replaced[i][0] is a tsocks fd and replaced[i][1] is an app
 * fd. If the tsocks fd is found in fds, then remove it from fds and add
 * the app fd. Free each array as we iterate over it, we won't need it again.
 */
static void poll_restore_fds_and_free(struct pollfd *fds, nfds_t nfds, int **replaced, int len)
{
	int i, j, count = 0;
	if (len == 0)
		return;
	for (i = 0; i < len; i++) {
		int cur_fd = replaced[i][0];
		for (j = 0; j < nfds; j++) {
			if (fds[j].fd == cur_fd) {
				fds[j].fd = replaced[i][1];
				count++;
			}
		}
		free(replaced[i]);
	}
	DBG("[poll] Restored %d descriptor%s in fds", count,
					   count == 1 ? "" : "s");
	free(replaced);
}

/*
 * Torsocks call for poll(2).
 */
LIBC_POLL_RET_TYPE tsocks_poll(LIBC_POLL_SIG)
{
	int **replaced_fds;
	int replaced_len = 0;
	int retval;

	DBG("[poll] Poll caught");
	/* Find all the fds in readfds whose connections we are currently
	 * hijacking and replace them with our tsocks fd.
	 *
	 * read_replaced_fds will be a list of (tor_fd, app_fd) pairs of
	 * all the fds we replaced, and it has a size of read_replaced_len.
	 */
	connection_conn_list_find_and_replace_poll(fds, nfds,
						&replaced_fds,
						&replaced_len);
	retval = tsocks_libc_poll(LIBC_POLL_ARGS);
	/* Replace each tsocks fd which has a pending event with
	 * its app fd, so the app knows it should take action.
	 */
	poll_restore_fds_and_free(fds, nfds, replaced_fds,
				    replaced_len);
	return retval;
}

/*
 * Torsocks call for ppoll(2).
 */
LIBC_PPOLL_RET_TYPE tsocks_ppoll(LIBC_PPOLL_SIG)
{
	int **replaced_fds;
	int replaced_len = 0;
	int retval;

	DBG("[ppoll] ppoll caught");
	/* Find all the fds in readfds whose connections we are currently
	 * hijacking and replace them with our tsocks fd.
	 *
	 * read_replaced_fds will be a list of (tor_fd, app_fd) pairs of
	 * all the fds we replaced, and it has a size of read_replaced_len.
	 */
	connection_conn_list_find_and_replace_poll(fds, nfds,
						&replaced_fds,
						&replaced_len);

	retval = tsocks_libc_ppoll(LIBC_PPOLL_ARGS);
	/* Replace each tsocks fd which has a pending event with
	 * its app fd, so the app knows it should take action.
	 */
	poll_restore_fds_and_free(fds, nfds, replaced_fds, replaced_len);
	return retval;
}

/*
 * Libc hijacked symbol poll(2).
 */
LIBC_POLL_DECL
{
	if (!tsocks_libc_poll) {
		tsocks_libc_poll = tsocks_find_libc_symbol(
				LIBC_POLL_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_poll(LIBC_POLL_ARGS);
}

/*
 * Libc hijacked symbol ppoll(2).
 */
LIBC_PPOLL_DECL
{
	if (!tsocks_libc_ppoll) {
		tsocks_libc_ppoll = tsocks_find_libc_symbol(
				LIBC_PPOLL_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_ppoll(LIBC_PPOLL_ARGS);
}
