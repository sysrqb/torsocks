#include <stdarg.h>
#include <common/log.h>
#include "torsocks.h"
#include <stdlib.h>

/* select(2) */
TSOCKS_LIBC_DECL(select, LIBC_SELECT_RET_TYPE, LIBC_SELECT_SIG)

/*
 * Replace tsocks fd with app fd
 *
 * *replaced* is a array of arrays. The arrays are of length two,
 * where replaced[i][0] is a tsocks fd and replaced[i][1] is an app
 * fd. If the tsocks fd is found in fds, then remove it from fds and add
 * the app fd. Free each array as we iterate over it, we won't need it again.
 */
static void select_restore_fds_and_free(fd_set *fds, int **replaced, int len)
{
	int i, count = 0;
	if (len == 0)
		return;
	for (i = 0; i < len; i++) {
		int cur_fd = replaced[i][0];
		if (FD_ISSET(cur_fd, fds)) {
			FD_CLR(cur_fd, fds);
			FD_SET(replaced[i][1], fds);
			count++;
		}
		free(replaced[i]);
	}
	DBG("[select] Restored %d fd in fd_set", count);
	free(replaced);
}

/*
 * Torsocks call for select(2).
 */
LIBC_SELECT_RET_TYPE tsocks_select(LIBC_SELECT_SIG)
{
	int new_nfds;
	int **read_replaced_fds, **write_replaced_fds;
	int **except_replaced_fds;
	int read_replaced_len = 0, write_replaced_len = 0;
	int except_replaced_len = 0;
	int retval;

	DBG("[select] Select caught");
	/* Find all the fds in readfds whose connections we are currently
	 * hijacking and replace them with our tsocks fd.
	 *
	 * read_replaced_fds will be a list of (tsocks_fd, app_fd) pairs of
	 * all the fds we replaced, and it has a size of read_replaced_len.
	 */
	new_nfds = connection_conn_list_find_and_replace(readfds,
							 &read_replaced_fds,
							 &read_replaced_len);
	if ((new_nfds + 1) > nfds)
		nfds = new_nfds + 1;
	new_nfds = connection_conn_list_find_and_replace(writefds,
							 &write_replaced_fds,
							 &write_replaced_len);
	if ((new_nfds + 1) > nfds)
		nfds = new_nfds + 1;
	new_nfds = connection_conn_list_find_and_replace(exceptfds,
							 &except_replaced_fds,
							 &except_replaced_len);
	if ((new_nfds + 1) > nfds)
		nfds = new_nfds + 1;

	retval = tsocks_libc_select(LIBC_SELECT_ARGS);
	/* Replace each tsocks fd which has a pending event with
	 * its app fd, so the app knows it should take action.
	 */
	select_restore_fds_and_free(readfds, read_replaced_fds,
				    read_replaced_len);
	select_restore_fds_and_free(writefds, write_replaced_fds,
				    write_replaced_len);
	select_restore_fds_and_free(exceptfds, except_replaced_fds,
				    except_replaced_len);
	return retval;
}

/*
 * Libc hijacked symbol select(2).
 */
LIBC_SELECT_DECL
{
	if (!tsocks_libc_select) {
		tsocks_libc_select = tsocks_find_libc_symbol(
				LIBC_SELECT_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_select(LIBC_SELECT_ARGS);
}
