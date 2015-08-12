/*
 * Copyright (C) 2013 - David Goulet <dgoulet@ev0ke.net>
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

#include <arpa/inet.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>

#include "connection.h"
#include "macros.h"
#include "utils.h"

int tsocks_destroy_event(struct connection *conn, struct event_specifier *evspec);

/*
 * Connection registry mutex.
 *
 * MUST be acquired for each read/write operation on the connection registry
 * declared below.
 *
 * This mutex is NOT nested anywhere.
 */
static TSOCKS_INIT_MUTEX(connection_registry_mutex);

/*
 * List of open FDs we are hijacking
 *
 * These are only the fds, the conn should be retrieved from the HT.
 */
struct connection_list {
	uint32_t len;
	uint32_t head;
	uint32_t num_used;
	int *fds;
} conn_list;

#define CONN_LIST_START_LEN 32

/*
 * Release connection using the given refcount located inside the connection
 * object. This is ONLY called from the connection put reference. After this
 * call, the connection object associated with that refcount object is freed.
 */
static void release_conn(struct ref *ref)
{
	struct connection *conn = container_of(ref, struct connection, refcount);
	connection_destroy(conn);
}

/*
 * Return 0 if the two connections are equal else 1.
 */
static inline int conn_equal_fct(struct connection *c1,
		struct connection *c2)
{
	return (c1->app_fd == c2->app_fd);
}

/*
 * Return a hash value based on the unique fd of the given connection.
 */
static inline unsigned int conn_hash_fct(struct connection *c)
{
	unsigned int mask;

	assert(c);

	switch (sizeof(mask)) {
	case 1:
		mask = 0xff;
		break;
	case 2:
		mask = 0xffff;
		break;
	case 4:
	default:
		mask = 0xffffffff;
		break;
	}

	return (((unsigned int)(c->app_fd) << 8) ^
				((unsigned int)((c->app_fd >> sizeof(mask)) & mask)) ^
				((unsigned int)(c->app_fd & mask)));
}

/*
 * Declare the connection registry.
 */
static HT_HEAD(connection_registry, connection) connection_registry_root = HT_INITIALIZER();
HT_PROTOTYPE(connection_registry, connection, node, conn_hash_fct,
		conn_equal_fct, app_fd);
HT_GENERATE(connection_registry, connection, node, conn_hash_fct,
		conn_equal_fct, 0.5, malloc, realloc, free);

/*
 * Acquire connection registry mutex.
 */
ATTR_HIDDEN
void connection_registry_lock(void)
{
	tsocks_mutex_lock(&connection_registry_mutex);
}

/*
 * Release connection registry mutex.
 */
ATTR_HIDDEN
void connection_registry_unlock(void)
{
	tsocks_mutex_unlock(&connection_registry_mutex);
}

/*
 * Set an already allocated connection address using the given IPv4/6 address,
 * domain and port.
 *
 * Return 0 on success or else a negative value.
 */
ATTR_HIDDEN
int connection_addr_set(enum connection_domain domain, const char *ipaddr,
		in_port_t port, struct connection_addr *addr)
{
	int ret;
	const char *path;

	assert(ipaddr);
	assert(addr);

	if (port == 0 || port >= 65535) {
		ret = -EINVAL;
		ERR("Connection addr set port out of range: %d", port);
		goto error;
	}

	memset(addr, 0, sizeof(*addr));

	switch (domain) {
	case CONNECTION_DOMAIN_INET:
		addr->domain = domain;
		addr->u.sin.sin_family = AF_INET;
		addr->u.sin.sin_port = htons(port);
		ret = inet_pton(addr->u.sin.sin_family, ipaddr,
				&addr->u.sin.sin_addr);
		if (ret != 1) {
			PERROR("Connection addr set inet_pton");
			ret = -EINVAL;
			goto error;
		}
		break;
	case CONNECTION_DOMAIN_INET6:
		addr->domain = domain;
		addr->u.sin6.sin6_family = AF_INET6;
		addr->u.sin6.sin6_port = htons(port);
		ret = inet_pton(addr->u.sin6.sin6_family, ipaddr,
				&addr->u.sin6.sin6_addr);
		if (ret != 1) {
			PERROR("Connection addr6 set inet_pton");
			ret = -EINVAL;
			goto error;
		}
		break;
	case CONNECTION_DOMAIN_UNIX:
		path = utils_unix_socket_path(ipaddr);
		addr->domain = domain;
		addr->u.sun.sun_family = AF_UNIX;
		if (path == NULL) {
			PERROR("Connection unix socket dup path");
			ret = -EINVAL;
			goto error;
		}
		memcpy(addr->u.sun.sun_path,
			path, strlen(path));
		break;
	default:
		ERR("Connection addr set unknown domain %d", domain);
		ret = -EINVAL;
		goto error;
	}

	/* Everything is set and good. */
	ret = 0;

error:
	return ret;
}

/*
 * Create a new connection with the given fd and destination address.
 *
 * Return a newly allocated connection object or else NULL.
 */
ATTR_HIDDEN
struct connection *connection_create(int fd, const struct sockaddr *dest)
{
	struct connection *conn = NULL;
	const struct sockaddr_in *in4;
	const struct sockaddr_in6 *in6;
	char dotted[128];

	conn = zmalloc(sizeof(*conn));
	if (!conn) {
		PERROR("zmalloc connection");
		goto error;
	}

	if (dest) {
		switch (dest->sa_family) {
		case AF_INET:
			conn->dest_addr.domain = CONNECTION_DOMAIN_INET;
			memcpy(&conn->dest_addr.u.sin, dest,
					sizeof(conn->dest_addr.u.sin));
			in4 = &conn->dest_addr.u.sin;
			inet_ntop(dest->sa_family, &in4->sin_addr, dotted, 128);
			DBG("Copied INET addr %#x (%s)", in4->sin_addr.s_addr, dotted);
			break;
		case AF_INET6:
			conn->dest_addr.domain = CONNECTION_DOMAIN_INET6;
			memcpy(&conn->dest_addr.u.sin6, dest,
					sizeof(conn->dest_addr.u.sin6));
			in6 = &conn->dest_addr.u.sin6;
			inet_ntop(dest->sa_family, &in6->sin6_addr, dotted, 128);
			DBG("Copied INET6 addr %#x (%s)", in6->sin6_addr.s6_addr, dotted);
			break;
		default:
			ERR("Connection domain unknown %d", dest->sa_family);
			goto error;
		}
	}

	conn->app_fd = fd;
	connection_get_ref(conn);

	return conn;

error:
	free(conn);
	return NULL;
}

/*
 * Clone (deep copy) an existing connection.
 *
 * Deep copy an existing connection and return a newly allocated connection
 * object or else NULL.
 */
#if 0
ATTR_HIDDEN
struct connection *connection_clone(const struct connection *conn)
{
	struct connection *new_conn = NULL;

	if (!conn)
		return NULL;
	conn = zmalloc(sizeof(*new_conn));
	if (!new_conn) {
		PERROR("zmalloc connection");
		goto error;
	}

	memcpy(conn, new_conn, sizeof(conn->app_fd) +
			       sizeof(conn->tsocks_fd) +
			       sizeof(conn->dest_addr) +
			       sizeof(conn->tsocks_addr));

	switch (conn->dest_addr.domain) {
	case CONNECTION_DOMAIN_NAME:
		new_conn->dest_addr.domain = CONNECTION_DOMAIN_NAME;
		new_conn->dest_addr.hostname.port = conn->dest_addr.hostname.port;
		new_conn->dest_addr.hostname.addr = strdup(conn->dest_addr.hostname.addr);
		if (!new_conn->dest_addr.hostname.addr) {
			ret_errno = ENOMEM;
			goto error_free;
		}
		break;
	case CONNECTION_DOMAIN_INET:
		new_conn->dest_addr.domain = CONNECTION_DOMAIN_INET;
		memcpy(&conn->dest_addr.u.sin, new_conn->dest_addr.u.sin,
				sizeof(new_conn->dest_addr.u.sin));
		break;
	case CONNECTION_DOMAIN_INET6:
		new_conn->dest_addr.domain = CONNECTION_DOMAIN_INET6;
		memcpy(&conn->dest_addr.u.sin6, new_conn->dest_addr.u.sin6,
				sizeof(new_conn->dest_addr.u.sin6));
		break;
	default:
		ERR("Bad connection domain found during conn clone: %d",
		    conn->dest_addr.domain);
		goto error;
	}
}
#endif

/*
 * Return the matching element with the given key or NULL if not found.
 */
ATTR_HIDDEN
struct connection *connection_find(int key)
{
	struct connection c_tmp;

	c_tmp.app_fd = key;
	return HT_FIND(connection_registry, &connection_registry_root, &c_tmp);
}

/*
 * Insert fd into the conn_list, the list of all application connections we're
 * currently intercepting. Increase conn_list's size if we're at its capacity.
 *
 * All unused indices should have a value of -1.
 */
static void connection_conn_list_insert(int fd)
{
	uint32_t i;
	if (fd < 0)
		return;
	if (conn_list.fds == NULL) {
		conn_list.fds = malloc(CONN_LIST_START_LEN*sizeof(*conn_list.fds));
		if (!conn_list.fds) {
			ERR("Could not alloc space for conn_list.");
			return;
		}
		conn_list.len = CONN_LIST_START_LEN;
		conn_list.head = 0;
		conn_list.num_used = 0;
		/* Initialize the array to -1 */
		memset(conn_list.fds, -1, conn_list.len);
	} else if (conn_list.len == conn_list.num_used) {
		errno = 0;
		conn_list.fds = realloc(conn_list.fds, conn_list.len*2);
		if (errno != 0) {
			ERR("Could not realloc more space for conn_list. %s",
			    strerror(errno));
			return;
		}
		/* Initialize the new memory to -1 */
		memset(conn_list.fds + conn_list.len, -1, conn_list.len);
		conn_list.len *= 2;
	}
	for (i=0; i < conn_list.len; ++i) {
		if (conn_list.fds[i] == -1) {
			DBG("Inserting fd %d into conn_list at %d.", fd, i);
			conn_list.fds[i] = fd;
			conn_list.num_used++;
			if (i > conn_list.head)
				conn_list.head = i;
			break;
		}
	}
}

/*
 * Remove fd from the conn_list.
 *
 * We reset the value in the conn_list as -1.
 *
 * This should only be called when we're certain we don't care about
 * it anymore.
 */
static void connection_conn_list_remove(int fd)
{
	int i;

	DBG("Removing fd %d from conn_list.", fd);
	if (fd < 0)
		return;
	if (conn_list.len == 0 || conn_list.num_used == 0 ||
	    conn_list.fds == NULL)
		return;
	for (i = 0; i < conn_list.head + 1; i++) {
		if (conn_list.fds[i] == fd) {
			conn_list.fds[i] = -1;
			conn_list.num_used--;
			DBG("Removed fd %d from conn_list at %d.", fd, i);
			if (i == conn_list.head) {
				/* Adjust head so it points to the highest
				 * used index in the array */
				while (i > -1) {
					if (conn_list.fds[i] != -1) {
						conn_list.head = i;
						break;
					}
					i--;
				}
			}
			break;
		}
	}
}

/*
 * For each application fd in fds, find the tsocks connection
 * corresponding to it. Remove the application fd and add the tsocks
 * connection.
 *
 * Returns the fd with the highest number
 */
ATTR_HIDDEN
int connection_conn_list_find_and_replace_select(fd_set *fds,
						int **replaced[], int *len)
{
	int i, max = -1, rep_idx=0;
	if (conn_list.len == 0 || conn_list.num_used == 0 ||
	    conn_list.fds == NULL)
		return max;
	if (fds == NULL)
		return max;
	*replaced = calloc(conn_list.num_used, sizeof(**replaced));
	if (*replaced == NULL) {
		DBG("Couldn't allocate space for replaced");
		*len = 0;
		return max;
	}
	for (i = 0; i < conn_list.head + 1; i++) {
		int fd = conn_list.fds[i];
		if (fd == -1)
			continue;
		if (FD_ISSET(fd, fds)) {
			struct connection *conn;
			conn = connection_find(fd);
			if (conn == NULL)
				/* This is a bug, but segfaulting is sad */
				continue;
			FD_CLR(fd, fds);
			FD_SET(conn->tsocks_fd, fds);
			DBG("Replaced fd %d with %d in fd_set.", fd, conn->tsocks_fd);
			if (conn->tsocks_fd > max)
				max = conn->tsocks_fd;
			(*replaced)[rep_idx] = calloc(2, sizeof(***replaced));
			if ((*replaced)[rep_idx] == NULL) {
				*len = rep_idx;
				return max;
			}
			(*replaced)[rep_idx][0] = conn->tsocks_fd;
			(*replaced)[rep_idx++][1] = fd;
		}
	}
	*len = rep_idx;
	return max;
}

/*
 * For each application fd in fds, find the tsocks connection
 * corresponding to it. Substitute the application fd with the tsocks
 * connection.
 */
ATTR_HIDDEN
void connection_conn_list_find_and_replace_poll(struct pollfd *fds, nfds_t nfds,
						int **replaced[], int *len)
{
	int i, j, rep_idx=0;

	if (conn_list.len == 0 || conn_list.num_used == 0 ||
	    conn_list.fds == NULL)
		return;
	if (fds == NULL)
		return;
	*replaced = calloc(conn_list.num_used, sizeof(**replaced));
	if (*replaced == NULL) {
		*len = 0;
		return;
	}
	for (i = 0; i < conn_list.head + 1; i++) {
		int fd = conn_list.fds[i];
		if (fd == -1)
			continue;
		for (j = 0; j < nfds; j++) {
			if (fd == fds[j].fd) {
				struct connection *conn;
				conn = connection_find(fd);
				if (conn == NULL)
					/* This is a bug, but segfaulting is sad */
					continue;
				fds[j].fd = conn->tsocks_fd;
				DBG("Replaced fd %d with %d in pollfd.", fd, conn->tsocks_fd);
				(*replaced)[rep_idx] = calloc(2, sizeof(***replaced));
				if ((*replaced)[rep_idx] == NULL) {
					*len = rep_idx;
					return;
				}
				(*replaced)[rep_idx][0] = conn->tsocks_fd;
				(*replaced)[rep_idx++][1] = fd;
			}
		}
	}
	*len = rep_idx;
}

/*
 * Insert a connection object into the hash table.
 */
ATTR_HIDDEN
void connection_insert(struct connection *conn)
{
	struct connection *c_tmp;

	assert(conn);

	/* An existing element is a code flow error. */
	c_tmp = connection_find(conn->app_fd);
	assert(!c_tmp);

	HT_INSERT(connection_registry, &connection_registry_root, conn);
	connection_conn_list_insert(conn->app_fd);
}

/*
 * Remove a given connection object from the registry.
 */
ATTR_HIDDEN
void connection_remove(struct connection *conn)
{
	assert(conn);
	HT_REMOVE(connection_registry, &connection_registry_root, conn);
	connection_conn_list_remove(conn->app_fd);
}

/*
 * Destroy a connection by freeing its memory.
 */
ATTR_HIDDEN
void connection_destroy(struct connection *conn)
{
	if (!conn) {
		return;
	}

	tsocks_destroy_all_events(conn);
	free(conn->dest_addr.hostname.addr);
	free(conn);
}

/*
 * Get a reference of the given connection object.
 */
ATTR_HIDDEN
void connection_get_ref(struct connection *c)
{
	ref_get(&c->refcount);
}

/*
 * Put back a reference of the given connection object. If the refcount drops
 * to 0, the release connection function is called which frees the object.
 */
ATTR_HIDDEN
void connection_put_ref(struct connection *c)
{
	ref_put(&c->refcount, release_conn);
}
