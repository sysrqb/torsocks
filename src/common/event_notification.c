/*
 * Copyright (C) 2015 - Matthew Finkel <Matthew.Finkel@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#include <errno.h>
#include "event_notification.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* Find and return an event specifier from the linked-list, or return NULL */
ATTR_HIDDEN
struct event_specifier *
tsocks_find_event_specifier_by_identifier(struct event_specifier *events,
					  event_id_t id)
{
	struct event_specifier *event = NULL;
	DBG("[events] Searching for evspec by id: %u, events %s%#x", id,
	    events == NULL ? "0x" : "", events);
	if (events == NULL)
		return NULL;
	for (event = events; event != NULL; event = event->next) {
		if (!memcmp(&event->id, &id, sizeof(event->id)))
			return event;
	}
	return NULL;
}

/* Find and return an event specifier from the linked-list, or return NULL */
ATTR_HIDDEN
struct event_specifier *
tsocks_find_event_specifier_by_efd(struct event_specifier *events,
				   int efd)
{
	struct event_specifier *event = NULL;
	DBG("[events] Searching for evspec by epd: %d, events %s%#x", efd,
	    events == NULL ? "0x" : "", events);
	if (events == NULL)
		return NULL;
	for (event = events; event != NULL; event = event->next) {
		if (event->efd == efd)
			return event;
	}
	return NULL;
}

/*
 * Return a string value describing the enum type for the current
 * mechanism.
 *
 * Caller must check that the returned value is not NULL on return.
 */
ATTR_HIDDEN
const char * tsocks_event_mech_to_string(event_mech_t mech)
{
	char *name;
	const uint8_t max_len = 40;
	const char *unknown_mech = "unknown mechanism: ";
	const size_t namelen = strlen(unknown_mech) + max_len;
	int ret;
	switch (mech) {
	case KQUEUE:
		name = strdup("kqueue");
		break;
	case KQUEUE64:
		name = strdup("kqueue64");
		break;
	case EPOLL:
		name = strdup("epoll");
		break;
	default:
		name = malloc(sizeof(*name)*namelen);
		if (name == NULL)
			break;
		ret = snprintf(name, namelen, "%s%d", unknown_mech, mech);
		if (ret < 0) {
			free(name);
			name = NULL;
			break;
		} 
	}

	return name;
}

/* Append evspec on the conn's event linked-list */
ATTR_HIDDEN
void tsocks_add_event_on_connection(struct connection *conn,
				    struct event_specifier *evspec)
{
	struct event_specifier *cur;
	int i = 0;
	if (conn->events == NULL) {
		conn->events = evspec;
		goto done;
	}
	for (cur = conn->events; cur != NULL; cur = cur->next) {
		if (cur->next == NULL) {
			cur->next = evspec;
			goto done;
		}
		i++;
	}
done:
	DBG("[events] Added evspec %#x at %d in linked-list.", evspec, i);
	return;
}

/*
 * Linux: Create and return a new event specifier and initialed with the
 * epoll values.
 * Any other kernel returns NULL.
 * Returns NULL on failure.
 */
ATTR_HIDDEN
struct event_specifier *
tsocks_create_new_event_epoll(int epfd, uint32_t events, epoll_data_t data)
{
#if defined(__linux__)
	struct event_specifier *spec = malloc(sizeof(*spec));
	if (spec == NULL) {
		DBG("[epoll] Failed to create new evspec.");
		return NULL;
	}
	spec->mech = EPOLL;
	spec->efd = epfd;
	spec->filters = events;
	spec->id = data;
	spec->marked_event_for_destroy = 0;
	spec->next = NULL;
	return spec;
#else
	return NULL;
#endif
}

/*
 * BSD: Create and return a new event specifier and initialed with the
 * kevent values.
 * Any other kernel returns NULL.
 * Returns NULL on failure.
 */
struct event_specifier *
tsocks_create_new_event_kqueue(int kq, uintptr_t id, int16_t filter)
{
#if (defined(__FreeBSD__) || defined(__darwin__) || defined(__NetBSD__))
	struct event_specifier *spec = malloc(sizeof(*spec));
	if (spec == NULL) {
		DBG("[kqueue] Failed to create new evspec.");
		return NULL;
	}
	spec->mech = KQUEUE;
	spec->efd = kq;
	spec->filters |= 1 << filter;
	spec->id = id;
	spec->marked_event_for_destroy = 0;
	spec->next = NULL;
	return spec;
#else
	return NULL;
#endif
}

/*
 * Darwin: Create and return a new event specifier and initialed with the
 * kevent values.
 * Any other kernel returns NULL.
 * Returns NULL on failure.
 */
struct event_specifier *
tsocks_create_new_event_kqueue64(int kq, uint64_t id, int16_t filter)
{
#if defined(__darwin__)
	struct event_specifier *spec = tsocks_create_new_event_kqueue(
						kq, 0, filter);
	if (spec == NULL) {
		DBG("[kqueue64] Failed to create new evspec.");
		return NULL;
	}
	spec->mech = KQUEUE64;
	spec->id = id;
	return spec;
#else
	return NULL;
#endif
}

/*
 * Find the provided evspec in the conn's events list. Remove that event
 * from the list and free it.
 * Return -1 on failure, return 0 on success.
 */
ATTR_HIDDEN
int tsocks_destroy_event(struct connection *conn,
			 struct event_specifier *evspec)
{
	struct event_specifier *curr, *prev = NULL;
	int destroyed = 0;
	if (evspec == NULL) {
		DBG("[events] Can't destroy NULL evspec");
		return -1;
	}
	if (!evspec->marked_event_for_destroy) {
		DBG("[events] evspec %#x not marked for destroy", evspec);
		return -1;
	}

	DBG("[events] Destroying evspec %#x", evspec);
	for (curr = conn->events; curr != NULL; curr = curr->next) {
		if (curr == evspec) {
			if (prev != NULL) {
				prev->next = curr->next;
			} else {
				if (curr->next == NULL) {
					conn->events = NULL;
				} else {
					conn->events = curr->next;
				}
			}
			free(curr);
			destroyed = 1;
			break;
		}
	}

	if (!destroyed) {
		/* It seems there's a bug :/ */
		DBG("[events] Received request for destroying event, but "
		    "it's not in our list!");
		return -1;
	}
	return 0;
}

/*
 * Destroy all evspec's in the conn's linked-list.
 * Return -1 on failure, return 0 on success.
 */
ATTR_HIDDEN
int tsocks_destroy_all_events(struct connection *conn)
{
	struct event_specifier *evspec, *prev_evspec;

	if (conn == NULL)
		return -1;
	evspec = conn->events;
	while (evspec != NULL) {
		evspec->marked_event_for_destroy = 1;
		prev_evspec = evspec;
		evspec = evspec->next;
		tsocks_destroy_event(conn, prev_evspec);
	}
	return 0;
}

/*
 * Modify evspec by the provided kevent kev. If the requested modification
 * isn't add, delete, or oneshot then do nothing. If the operation is
 * add, then add the new filter in evspec. Delete deletes the filter from
 * evspec. Oneshot adds the filter in a special bitmap filter_oneshot which
 * clears the filter on its first occurrence.
 * If requested modification is DELETE and this results in filter == 0, then
 * destroy evspec.
 * Return -1 on error, return 0 on success.
 */
static int modify_event_kqueue(struct event_specifier *evspec,
				const struct kevent *kev,
				struct connection *conn)
{
#if (defined(__FreeBSD__) || defined(__darwin__) || defined(__NetBSD__) || defined(__darwin__))
	if (kev == NULL) {
		DBG("[kqueue] Can't modify evspec when given NULL kev pointer. :(");
		return -1;
	}
	if (evspec == NULL) {
		DBG("[kqueue] Can't modify evspec when given NULL evspec pointer. :(");
		return -1;
	}
	if (memcmp(evspec->id, kev->ident, sizeof(evspec->id))) {
		DBG("[kqueue] This kev's ID doesn't match what we know. Abort.");
		return -1;
	}
	if (!(kev->flags & (EV_ADD|EV_DELETE|EV_ONESHOT))) {
		DBG("[kqueue] Modification not needed, skipping.");
		return -1;
	}
	if (kev->flags & EV_ADD) {
		evspec->filters |= 1 << -kev->filter;
	} else if (kev->flags & EV_DELETE) {
		evspec->filters &= ~(1 << -kev->filter);
		if (evspec->filters == 0 && evspec->oneshot_filters == 0) {
			evspec->marked_event_for_destroy = 1;
		}
	}
	} else if (kev->flags & EV_ONESHOT) {
		evspec->oneshot_filters &= ~(1 << -kev->filter);
	} else {
		/* Should not be possible */
		return -1;
	}
	return 0;
#else
	return -1;
#endif
}
	
/*
 * Modify evspec by the provided epoll_event. If the requested modification
 * isn't add, modify, or delete then do nothing. If the operation is
 * add or mod, then add the new filter in evspec. Delete deletes the filter
 * from evspec.
 * If op is delete and this results in filter == 0, then destroy evspec.
 * Return -1 on error, return 0 on success.
 */
static int modify_event_epoll(int fd, int op, struct event_specifier *evspec,
				const struct epoll_event *event,
				struct connection *conn)
{
#if defined(__linux__)
	errno = 0;
	if (evspec == NULL) {
		DBG("[epoll] Can't modify evspec when given NULL evspec pointer. :(");
		errno = EINVAL;
		return -1;
	}
	if (conn->tsocks_fd != fd) {
		DBG("[epoll] This event's ID doesn't match what we know. "
		    "%d vs %d. Abort.", conn->app_fd, fd);
		errno = EINVAL;
		return -1;
	}
	if (op != EPOLL_CTL_ADD && op != EPOLL_CTL_MOD && op != EPOLL_CTL_DEL) {
		DBG("[epoll] Operation not recognized or supported (%d). "
		    "Skipping.", op);
		errno = EINVAL;
		return -1;
	}
	if (op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD) {
		if (event == NULL) {
			DBG("[epoll] Can't modify evspec when given NULL event pointer. :(");
			errno = EINVAL;
			return -1;
		}
		/* epoll's ONESHOT is different from kqueue. Here Oneshot
		 * disables the polling, it doesn't automatically delete it.
		 * We ignore EPOLLONESHOT because it doesn't change how we
		 * handle the call. */
		evspec->filters |= event->events;
	} else {
		/* Should only be EPOLL_CTL_DEL */
		evspec->marked_event_for_destroy = 1;
	}
	return 0;
#else
	return -1
#endif
}

/*
 * Modify evspec as requested. If evspec is for KQUEUE{,64} then pass the
 * request modify_event_kqueue(). If evspec is for EPOLL, then pass the
 * request to modify_event_epoll().
 * efd is the kq or epfd file descriptor, op is the specified operation for
 * epoll and is ignored for kqueue. evspec is the event specifier we're
 * modifying. kev is the kevent defining the modification if we're using KQUEUE
 * or its ignored if not. epoll_event is the epoll_event defining the
 * modification if we're using EPOLL or its ignored if not. conn is the
 * connection on which this evspec is monitoring.
 */
ATTR_HIDDEN
int tsocks_modify_event(int efd, int fd, int op, struct event_specifier *evspec,
			const struct kevent *kev,
			const struct epoll_event *epoll_event,
			struct connection *conn)
{
	int success = -1;
	errno = 0;
	if (evspec == NULL) {
		DBG("[events] That's strange, a nul evspec is only good for crashing.");
		return -1;
	}
	if (evspec->efd != efd) {
		const char *name = tsocks_event_mech_to_string(evspec->mech);
		DBG("[events] That's strange, the %s file descriptor changed. That "
		    "shouldn't happen without torsocks detecting it.",
		    name != NULL ? name : "<unrecognized mech>");
		/* This isn't good, but it isn't fail worthy, but it is
		 * probably a bug. */
	}
	switch (evspec->mech) {
	case KQUEUE:
	case KQUEUE64:
		success = modify_event_kqueue(evspec, kev, conn);
		break;
	case EPOLL:
		success = modify_event_epoll(fd, op, evspec, epoll_event, conn);
		break;
	default:
		DBG("[events] Unknown mechanism can't be modified: %d", evspec->mech);
		break;
	}
	return success;
}
