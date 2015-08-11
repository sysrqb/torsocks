#include <stdarg.h>
#include <common/log.h>
#include "torsocks.h"
#include <common/connection.h>
#include <common/event_notification.h>

#define operation_name(op, operation)			\
	do {						\
		switch (op) {				\
		case EPOLL_CTL_ADD:			\
			operation = "ADD";		\
			break;				\
		case EPOLL_CTL_MOD:			\
			operation = "MOD";		\
			break;				\
		case EPOLL_CTL_DEL:			\
			operation = "DEL";		\
			break;				\
		default:				\
			operation = "<unrecognized>";	\
		}					\
	} while (0)			

/* epoll_ctl(2) */
TSOCKS_LIBC_DECL(epoll_ctl, LIBC_EPOLL_CTL_RET_TYPE, LIBC_EPOLL_CTL_SIG)

/*
 * Torsocks call for epoll_ctl(2).
 */
LIBC_EPOLL_CTL_RET_TYPE tsocks_epoll_ctl(LIBC_EPOLL_CTL_SIG)
{
	int eno;
	struct connection *conn;
	struct event_specifier *evspec;
	const char *operation;
	operation_name(op, operation);
	

	DBG("[epoll_ctl] epoll_ctl caught, epfd '%d', op '%s' (%d), fd %d, "
	    "events %u", epfd, operation, op, fd, event ? event->events : 0);

	conn = connection_find(fd);
	if (!conn) {
		/* We're not tracking this fd */
		return tsocks_libc_epoll_ctl(LIBC_EPOLL_CTL_ARGS);
	}
	fd = conn->tsocks_fd;
	DBG("Found conn %#x with tsocks fd %d", conn, fd);
	if (EPOLL_CTL_ADD == op) {
		evspec = tsocks_create_new_event_epoll(epfd,
						event->events,
						event->data);
		if (evspec == NULL) {
			DBG("[epoll_ctl] Creating new evspec failed. "
			    "'%s'", strerror(errno));
			errno = ENOMEM;
			return -1;
		}
		tsocks_add_event_on_connection(conn, evspec);
	} else if (EPOLL_CTL_DEL == op) {
		evspec = tsocks_find_event_specifier_by_efd(conn->events,
							    epfd);
	} else {
		evspec = tsocks_find_event_specifier_by_identifier(conn->events,
								   event->data);
	}

	if (evspec == NULL) {
		/* Hopefully this isn't a bug - but it
		 * probably is. */
		DBG("[epoll_ctl] Did not find existing evspec "
		    "in list.");
		errno = ENOENT;
		return -1;
	}

	if (tsocks_modify_event(epfd, fd, op, evspec, NULL,
				event, conn) == -1) {
			DBG("[epoll_ctl] Could not modify evspec. ");
			return -1;
	}
	if (tsocks_libc_epoll_ctl(LIBC_EPOLL_CTL_ARGS) == -1) {
		eno = errno;
		DBG("[epoll_ctl] epoll_ctl failed. '%s'", strerror(errno));
		errno = eno;
		if (evspec->marked_event_for_destroy)
			evspec->marked_event_for_destroy = 0;
		return -1;
	}
	if (evspec->marked_event_for_destroy)
		if (tsocks_destroy_event(conn, evspec) == -1)
			DBG("[epoll_ctl] evspec destroy failed.");
	return 0;
}

/*
 * Libc hijacked symbol epoll_ctl(2).
 */
LIBC_EPOLL_CTL_DECL
{
	if (!tsocks_libc_epoll_ctl) {
		tsocks_libc_epoll_ctl = tsocks_find_libc_symbol(
				LIBC_EPOLL_CTL_NAME_STR, TSOCKS_SYM_EXIT_NOT_FOUND);
	}

	return tsocks_epoll_ctl(LIBC_EPOLL_CTL_ARGS);
}
