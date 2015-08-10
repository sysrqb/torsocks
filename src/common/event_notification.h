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


/* This file provides a common interface for all of the event-driven poll
 * implementations we support.
 */

#ifndef TORSOCKS_EVENT_NOTIFICATION_H
#define TORSOCKS_EVENT_NOTIFICATION_H

#include "connection.h"

#if defined(__linux__)
#include <sys/epoll.h>
typedef epoll_data_t event_id_t;
struct kevent;
#elif (defined(__FreeBSD__) || defined(__darwin__) || defined(__NetBSD__))
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
typedef union event_id {
	uintptr_t kq;
	uint64_t kq64;
} event_id_t;
struct epoll_data;
#endif

/* The event mechanisms currently supported */
typedef enum event_mech {
	KQUEUE,
	KQUEUE64,
	EPOLL,
} event_mech_t;

/*
 * An object representing an event and its associated data
 * that we use for correctly intercepting, handling, and manipulating
 * syscall requests and responses.
 */
struct event_specifier;
struct event_specifier {
	/* The event file descriptor provided by the kernel. epfd for
	 * epoll, kq on *BSD and OS X. */
	int efd;
	/* The mechanism used by this kernel. */
	event_mech_t mech;
	/* A bitmap of the filters/events in which we're interested */
	uint32_t filters;
	uint32_t oneshot_filters;
	/* The identifier provided by the application */
	event_id_t id;
	/* Next event spec in linked-list */
	struct event_specifier *next;
};

struct event_specifier *
tsocks_find_event_specifier_by_identifier(struct event_specifier *events,
					  event_id_t id);
const char * tsocks_event_mech_to_string(event_mech_t mech);
void tsocks_add_event_on_connection(struct connection *conn,
				    struct event_specifier *evspec);
struct event_specifier *
tsocks_create_new_event_epoll(int epfd, uint32_t events, epoll_data_t data);
struct event_specifier *
tsocks_create_new_event_kqueue(int kq, uintptr_t id, int16_t filter);
struct event_specifier *
tsocks_create_new_event_kqueue64(int kq, uint64_t id, int16_t filter);
int tsocks_modify_event(int efd, int fd, int op, struct event_specifier *evspec,
			const struct kevent *kev,
			const struct epoll_event *epoll_event,
			struct connection *conn);

#endif /* TORSOCKS_EVENT_NOTIFICATION_H */
