#include <stdarg.h>
#include <common/log.h>
#include "torsocks.h"

#if (defined(__FreeBSD__) || defined(__darwin__) || defined(__NetBSD__))
/* kevent(2) */
TSOCKS_LIBC_DECL(kevent, LIBC_KEVENT_RET_TYPE, LIBC_KEVENT_SIG)
#if defined(__darwin__)
/* kevent64(2) */
TSOCKS_LIBC_DECL(kevent64, LIBC_KEVENT64_RET_TYPE, LIBC_KEVENT64_SIG)
#endif

static char * stringify_filter(short filter)
{
	switch (filter) {
	case EVFILT_READ:
		return strdup("EVFILT_READ");
	case EVFILT_WRITE:
		return strdup("EVFILT_WRITE");
	case EVFILT_AIO:
		return strdup("EVFILT_AIO");
	case EVFILT_VNODE:
		return strdup("EVFILT_VNODE");
	case EVFILT_PROC:
		return strdup("EVFILT_PROC");
	case EVFILT_SIGNAL:
		return strdup("EVFILT_SIGNAL");
	case EVFILT_TIMER:
		return strdup("EVFILT_TIMER");
	case EVFILT_USER:
		return strdup("EVFILT_USER");
	default:
		return strdup("<unknown filter>");
	}
}

/*
 * For each application fd in fds, find the tsocks connection
 * corresponding to it. Substitute the application fd with the tsocks
 * connection.
 */
static int kevent_find_and_replace(struct kevent *changes, int replaced[],
				int index, const struct connection *conn)
{
	int i;

	if (changes == NULL)
		return -1;
	if (*replaced == NULL)
		return -1;
	int fd = changes->ident;
	changes->ident = conn->tsocks_fd;
	DBG("Replaced fd %d with %d in kevent.", fd, conn->tsocks_fd);
	(*replaced)[index][0] = conn->tsocks_fd;
	(*replaced)[index][1] = fd;
	return 0;
}

/*
 * Replace tsocks fd with app fd
 *
 * *replaced* is a array of arrays. The arrays are of length two,
 * where replaced[i][0] is a tsocks fd and replaced[i][1] is an app
 * fd. If the tsocks fd is found in fds, then remove it from fds and add
 * the app fd. Free each array as we iterate over it, we won't need it again.
 */
static void kevent_restore_fds_and_free(struct kevent *events, int nevents,
					int **replaced, int len)
{
	int i, j, count = 0;
	if (len == 0)
		return;
	for (i = 0; i < len; i++) {
		int cur_fd = replaced[i][0];
		for (j = 0; j < nevents; j++) {
			if (events[j].ident == cur_fd) {
				kevent[j].ident = replaced[i][1];
				count++;
			}
		}
	}
	DBG("[kevent] Restored %d descriptor%s in fds", count,
					   count == 1 ? "" : "s");
	for (i = 0; i < len; i++)
		free(replaced[i]);
	free(replaced);
}

static int kevent_apply_changes(int kq, struct event_specifier *pending,
				struct connection *conn)
{
	struct event_specifier *evspec =
			tsocks_find_event_specifier_by_efd(conn->events, kq);
	if (evspec == NULL) {
		return -1;
	}
	if (pending->marked_event_for_destroy) {
		evspec->filters &= ~pending->filters;
	} else {
		evspec->filters |= pending->filters;
	}

	return 0;
}

static int kevent_delete_used_oneshot_events(eventlist[i], conn)
{
	struct event_specifier *evspec =
			tsocks_find_event_specifier_by_efd(conn->events, kq);
	for 
	evspec &= ~eventlist
	
	return 0;
}

/*
 * Torsocks call for kevent(2).
 */
LIBC_KEVENT_RET_TYPE tsocks_kevent(LIBC_KEVENT_SIG)
{
	int fds;
	int i, n, fds;
	int **replaced_fds;
	int replaced_len = 0;
	struct event_specifier *pending_changes = NULL,
				*pending_oneshot_changes = NULL;
	const uint8_t events = ((1<<-EVFILT_READ) | (1<<-EVFILT_WRITE) |
				(1<<-EVFILT_VNODE)); 

	DBG("[kevent] kevent caught with in-size '%d', and out-size '%d'",
	    nchanges, nevents);
	for (i=0; i < nchanges; i++) {
		if ((1<<-changelist[i].filter) & events) {
			struct event_specifier *evspec;
			DBG("[kevent] This filter interests us: %s",
			     stringify_filter(changelist[i].filter));
			conn = connection_find(changelist[i].ident);
			if (conn == NULL) {
				DBG("[kevent] Skipping, we don't care"
				    "about this fd");
				continue;
			}
			if (changelist[i].flags &
					(EV_ADD|EV_DELETE|EV_ONESHOT)) {
				DBG("[kevent] Adding, deleting, or oneshot "
				    "event");
				evspec = tsocks_create_new_event_kqueue(kq,
							changelist[i].ident,
							changelist[i].filter);
				if (evspec == NULL) {
					DBG("[kevent] evspec creation failed: %s",
				    	strerror(errno));
					goto free_end;
				}
				if (changelist[i].flags & EV_ONESHOT) {
					evspec->next = pending_oneshot_changes;
					pending_oneshot_changes = evspec;
					
				} else {
					evspec->marked_event_for_destroy =
						(changelist[i].flags &
							EV_DELETE);
					evspec->next = pending_changes;
					pending_changes = evspec;
				}
				/* Find all the idents (fds) in changelist whose
				 * connections we are currently hijacking and
				 * replace them with our tsocks fd. 
				 *
				 * replaced_fds will be a list of
				 * (tsocks_fd, app_fd) pairs of all the fds we
				 * replaced, and it has a size of
				 * replaced_len.
				 */
				(*replaced_fds)[replaced_len] =
					calloc(2, sizeof((*replaced_fds)[0]));
				if ((*replaced_fds)[replaced_len] == NULL) {
					eventlist[0].ident =
							changelist[i].ident;
					eventlist[0].flags = EV_ERROR;
					eventlist[0].data = ENOMEM;
					fds = 1;
					goto error_freeall;
				}
				if (kevent_find_and_replace(&changelist[i], 1,
						&replaced_fds[replaced_len++],
						1, conn) == -1) {
					continue;
				}
			}
		}
	}
	fds = tsocks_libc_kevent(LIBC_KEVENT_ARGS);
	if (fd == -1) {
		DBG("[kevent] kevent failed. '%s'", strerror(errno));
		n = nevents;
	} else {
		DBG("[kevent] kevent returned fd %d", fd);
		n = fds;
	}
	kevent_restore_fds_and_free(eventlist, n, replaced_fds, replaced_len);
	for (i = 0; i < n; i++) {
		struct eventspec *evspec;
		struct connection *conn = find_connection(
						eventlist[i].ident);
		if (conn == NULL)
			continue;
		if (eventlist[i]->flags & EVERR)
			continue;
		evspec = tsocks_find_event_specifier_by_identifier(
						pending_changes,
						event[i].ident)
		if (evspec != NULL) {
			kevent_apply_changes(kq, evspec, conn);
		}
		evspec = tsocks_find_event_specifier_by_identifier(
						pending_oneshot_changes,
						event[i].ident)
		if (evspec != NULL) {
			struct connection pseudo_conn;
			pseudo_conn.events = pending_oneshot_changes;
			tsocks_destroy_event(&pseudo_conn, evspec);
		}
		kevent_delete_used_oneshot_events(eventlist[i], conn);
		kevent_add_remaining_oneshot_events(eventlist[i], conn,
						pending_oneshot_changes);
	}

error_freeall:
	{
		struct connection pseudo_conn;
		pseudo_conn.events = pending_changes;
		tsocks_destroy_all_events(&pseudo_conn);

		pseudo_conn.events = pending_oneshot_changes;
		tsocks_destroy_all_events(&pseudo_conn);
	}

	return fds;
}

#if defined(__darwin__)
/*
 * Torsocks call for kevent64(2).
 */
LIBC_KEVENT_RET_TYPE tsocks_kevent64(LIBC_KEVENT64_SIG)
{
	int fd;

	DBG("[kevent64] kevent64 caught with flags '%d'", flags);

	fd = tsocks_libc_kevent64(LIBC_KEVENT64_ARGS);
	if (fd == -1) {
		DBG("[kevent64] kevent64 failed. '%s'", strerror(errno));
	} else {
		DBG("[kevent64] kevent64 returned fd %d", fd);
	}
	return fd;
}
#endif

/*
 * Libc hijacked symbol kevent(2).
 */
LIBC_KEVENT_DECL
{
	if (!tsocks_libc_kevent) {
		tsocks_libc_kevent = tsocks_find_libc_symbol(
				LIBC_KEVENT_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_kevent(LIBC_KEVENT_ARGS);
}

#if defined(__darwin__)
/*
 * Libc hijacked symbol kevent64(2).
 */
LIBC_KEVENT64_DECL
{
	if (!tsocks_libc_kevent64) {
		tsocks_libc_kevent64 = tsocks_find_libc_symbol(
				LIBC_KEVENT64_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_kevent64(LIBC_KEVENT64_ARGS);
}
#endif /* __darwin__ */
#endif /* __FreeBSD__, __darwin__, __NetBSD__ */
