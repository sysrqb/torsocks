#include <stdarg.h>
#include <common/log.h>
#include "torsocks.h"
#include <stdlib.h>

/* poll(2) */
TSOCKS_LIBC_DECL(poll, LIBC_POLL_RET_TYPE, LIBC_POLL_SIG)
#if (defined(__linux__))
/* ppoll(2) */
TSOCKS_LIBC_DECL(ppoll, LIBC_PPOLL_RET_TYPE, LIBC_PPOLL_SIG)
#endif /* __linux__ */

/*
 * For each application fd in fds, find the tsocks connection
 * corresponding to it. Substitute the application fd with the tsocks
 * connection.
 */
static void poll_find_and_replace(struct pollfd *fds, nfds_t nfds,
					int **replaced[], int *len)
{
	int i, rep_idx=0;

	if (fds == NULL)
		return;
	*replaced = calloc(nfds, sizeof(**replaced));
	if (*replaced == NULL) {
		*len = 0;
		return;
	}
	for (i = 0; i < nfds; i++) {
		int fd = fds[i].fd;
		struct connection *conn;
		conn = connection_find(fd);
		if (conn == NULL)
			continue;
		fds[i].fd = conn->tsocks_fd;
		DBG("Replaced fd %d with %d in pollfd.", fd, conn->tsocks_fd);
		(*replaced)[rep_idx] = calloc(2, sizeof(***replaced));
		if ((*replaced)[rep_idx] == NULL) {
			*len = rep_idx;
			return;
		}
		(*replaced)[rep_idx][0] = conn->tsocks_fd;
		(*replaced)[rep_idx++][1] = fd;
	}
	*len = rep_idx;
}

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
	}
	DBG("[poll] Restored %d descriptor%s in fds", count,
					   count == 1 ? "" : "s");
	for (i = 0; i < len; i++)
		free(replaced[i]);
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
	 * read_replaced_fds will be a list of (tsocks_fd, app_fd) pairs of
	 * all the fds we replaced, and it has a size of read_replaced_len.
	 */
	poll_find_and_replace(fds, nfds, &replaced_fds, &replaced_len);
	retval = tsocks_libc_poll(LIBC_POLL_ARGS);
	/* Replace each tsocks fd which has a pending event with
	 * its app fd, so the app knows it should take action.
	 */
	poll_restore_fds_and_free(fds, nfds, replaced_fds,
				    replaced_len);
	return retval;
}

#if (defined(__linux__))
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
	 * read_replaced_fds will be a list of (tsocks_fd, app_fd) pairs of
	 * all the fds we replaced, and it has a size of read_replaced_len.
	 */
	poll_find_and_replace(fds, nfds, &replaced_fds, &replaced_len);

	retval = tsocks_libc_ppoll(LIBC_PPOLL_ARGS);
	/* Replace each tsocks fd which has a pending event with
	 * its app fd, so the app knows it should take action.
	 */
	poll_restore_fds_and_free(fds, nfds, replaced_fds, replaced_len);
	return retval;
}
#endif /* __linux__ */

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

#if (defined(__linux__))
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
#endif /* __linux__ */
