/*
 * Copyright (C) 2014 - David Goulet <dgoulet@ev0ke.net>
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
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>

#include <lib/torsocks.h>

#include <tap/tap.h>

#define NUM_TESTS 34

#define TEST1_SETUP(granularity)			\
	do {						\
		FD_SET(pipe_fds[0], &readfds);		\
		FD_SET(pipe_fds[1], &readfds);		\
		FD_SET(pipe_fds[0], &writefds);		\
		FD_SET(pipe_fds[1], &writefds);		\
		FD_SET(pipe_fds[0], &exceptfds);	\
		FD_SET(pipe_fds[1], &exceptfds);	\
		tv.tv_sec = 0;				\
		tv.tv_ ##granularity = 0;		\
		now = time(NULL);			\
	} while (0)

#define TEST1_TESTS(vers)				\
	do {						\
		ok(ret != -1 && (time(NULL) - now) < 2,	\
		   #vers " returned without error");	\
		ok(!FD_ISSET(pipe_fds[0], &readfds),	\
		   "Read end of pipe has no data");	\
		ok(FD_ISSET(pipe_fds[1], &writefds),	\
		   "Write end of pipe is writable");	\
							\
		ret = write(pipe_fds[1], "test",	\
			    strlen("test"));		\
		ok(ret != 1, "Write failed on pipe.");	\
	} while (0)

#define TEST2_SETUP(granularity)		\
	do {					\
		FD_SET(pipe_fds[0], &readfds);	\
		tv.tv_sec = 0;			\
		tv.tv_ ##granularity = 0;	\
		now = time(NULL);		\
	} while (0)				\

#define TEST2_TESTS(vers)					\
	do {							\
		ok(ret != -1 && (time(NULL) - now) < 2,		\
		   #vers " returned without error, again");	\
		ok(FD_ISSET(pipe_fds[0], &readfds),		\
		   "Read end of pipe has data");		\
		ok(FD_ISSET(pipe_fds[1], &writefds),		\
		   "Write end of pipe is still writable");	\
	} while (0)

#define PIPE_SETS_REFRESH()		\
	do {				\
		close(pipe_fds[0]);	\
		close(pipe_fds[1]);	\
		pipe_fds[0] = -1;	\
		pipe_fds[1] = -1;	\
		FD_ZERO(&readfds);	\
		FD_ZERO(&writefds);	\
		FD_ZERO(&exceptfds);	\
	} while (0)

#define TEST3_SETUP(granularity)				\
	do {							\
		/* Create inet socket. */			\
		inet_sock = socket(AF_INET, SOCK_STREAM, 0);	\
		ok(inet_sock >= 0, "Inet socket created");	\
								\
		/* Create another inet socket. */		\
		inet_sock2 = socket(AF_INET, SOCK_STREAM, 0);	\
		ok(inet_sock2 >= 0, "Inet socket 2 created");	\
								\
		/* Create another inet socket. */		\
		inet_sock3 = socket(AF_INET, SOCK_STREAM, 0);	\
		ok(inet_sock3 >= 0, "Inet socket 3 created");	\
								\
		/* Connect socket through Tor so we can test	\
		 * the wrapper. */ 				\
		addrv4.sin_family = AF_INET;			\
		addrv4.sin_port = htons(443);			\
		inet_pton(addrv4.sin_family, ip,		\
			  &addrv4.sin_addr); 			\
		memset(addrv4.sin_zero, 0,			\
			sizeof(addrv4.sin_zero));		\
								\
		ret = connect(inet_sock,			\
			      (struct sockaddr *) &addrv4,	\
			      sizeof(addrv4));			\
		if (ret < 0) {					\
			fail("Unable to connect to %s", ip);	\
			goto error;				\
		}						\
								\
		FD_SET(inet_sock, &readfds);			\
		tv.tv_sec = 0;					\
		tv.tv_ ##granularity = 0;			\
		now = time(NULL);				\
	} while (0)

#define TEST3_TESTS(vers)					\
	do {							\
		ok(ret != -1 && (time(NULL) - now) < 2,		\
		   #vers " with inet socket returned without "	\
		   "error");					\
		ok(!FD_ISSET(inet_sock, &readfds),		\
		   "inet socket has no data needing reading");	\
		ok(!FD_ISSET(inet_sock, &writefds),		\
		   "inet socket not in writable fd set");	\
		ok(!FD_ISSET(inet_sock, &exceptfds),		\
		   "inet socket not in exception fd set");	\
	} while (0)

#define TEST4_SETUP(granularity)		\
	do {					\
		FD_ZERO(&readfds);		\
		FD_SET(inet_sock, &writefds);	\
		tv.tv_sec = 0;			\
		tv.tv_ ##granularity = 0;	\
		now = time(NULL);		\
	} while (0)

#define TEST4_TESTS(vers)					\
	do {							\
		ok(ret != -1 && (time(NULL) - now) < 2,		\
		   #vers " with inet socket returned without "	\
		   "error");					\
		ok(!FD_ISSET(inet_sock, &readfds),		\
		   "inet socket has no data needing reading");	\
		ok(FD_ISSET(inet_sock, &writefds),		\
		   "inet socket not in writable fd set");	\
		ok(!FD_ISSET(inet_sock, &exceptfds),		\
		   "inet socket not in exception fd set");	\
	} while (0)

#define TEST5_SETUP(granularity)		\
	do {					\
		FD_ZERO(&writefds);		\
		FD_SET(inet_sock, &exceptfds);	\
		tv.tv_sec = 0;			\
		tv.tv_ ##granularity = 0;	\
		now = time(NULL);		\
	} while (0)

#define TEST567_TESTS(vers)					\
	do {							\
		ok(ret != -1 && (time(NULL) - now) < 2,		\
		   #vers " with inet socket returned without "	\
		   "error");					\
		ok(!FD_ISSET(inet_sock, &readfds),		\
		   "inet socket has no data needing reading");	\
		ok(!FD_ISSET(inet_sock, &writefds),		\
		   "inet socket not in writable fd set");	\
		ok(!FD_ISSET(inet_sock, &exceptfds),		\
		   "inet socket has no exception");		\
	} while (0)


#define TEST6_SETUP(granularity)					\
	do {								\
		ret = connect(inet_sock2, (struct sockaddr *) &addrv4,	\
			      sizeof(addrv4));				\
		if (ret < 0) {						\
			fail("Unable to connect to %s", ip);		\
			goto error;					\
		}							\
									\
		ret = connect(inet_sock3, (struct sockaddr *) &addrv4,	\
			      sizeof(addrv4));				\
		if (ret < 0) {						\
			fail("Unable to connect to %s", ip);		\
			goto error;					\
		}							\
									\
		FD_SET(inet_sock, &readfds);				\
		FD_SET(inet_sock2, &readfds);				\
		tv.tv_sec = 0;						\
		tv.tv_ ##granularity = 0;				\
		now = time(NULL);					\
	} while (0)

#define TEST7_SETUP(granularity)					\
	do {								\
		close(inet_sock3);					\
		close(inet_sock2);					\
									\
		ret = pipe(pipe_fds);					\
		if (ret < 0) {						\
			fail("Unable to create pipe 2");		\
			goto error;					\
		}							\
		ok(pipe_fds[0] > 0 && pipe_fds[1] > 0,			\
		   "new pipe created");					\
									\
		/* Create another inet socket. */			\
		inet_sock2 = socket(AF_INET, SOCK_STREAM, 0);		\
		ok(inet_sock2 >= 0, "Inet socket 2 created");		\
									\
		/* Create another inet socket. */			\
		inet_sock3 = socket(AF_INET, SOCK_STREAM, 0);		\
		ok(inet_sock3 >= 0, "Inet socket 3 created");		\
									\
		ret = connect(inet_sock2, (struct sockaddr *) &addrv4,	\
			      sizeof(addrv4));				\
		if (ret < 0) {						\
			fail("Unable to connect to %s", ip);		\
			goto error;					\
		}							\
									\
		ret = connect(inet_sock3, (struct sockaddr *) &addrv4,	\
			      sizeof(addrv4));				\
		if (ret < 0) {						\
			fail("Unable to connect to %s", ip);		\
			goto error;					\
		}							\
									\
		FD_SET(inet_sock, &readfds);				\
		FD_SET(inet_sock2, &readfds);				\
		tv.tv_sec = 0;						\
		tv.tv_ ##granularity = 0;				\
		now = time(NULL);					\
	} while (0)


static void test_select(void)
{
	int pipe_fds[2], ret;
	int inet_sock = -1, inet_sock2 = -1, inet_sock3 = -1;
	struct sockaddr_in addrv4;
	const char *ip = "93.95.227.222";
	fd_set readfds, writefds, exceptfds;
	struct timeval tv;
	time_t now;

	ret = pipe(pipe_fds);
	if (ret < 0) {
		fail("Unable to create pipe");
		goto error;
	}

	/* This test is to see if we go through the libc or not. */
	ret = getpeername(pipe_fds[0], NULL, NULL);
	ok(ret == -1 && errno == ENOTSOCK, "Invalid socket fd");

        TEST1_SETUP(usec);

	/* Now let's see if we return immediately and successfully */
	ret = select(pipe_fds[1] + 1, &readfds, &writefds, &exceptfds, &tv);
	TEST1_TESTS(select);

	TEST2_SETUP(usec);
	ret = select(pipe_fds[1] + 1, &readfds, &writefds, &exceptfds, &tv);
	TEST2_TESTS(select);

	PIPE_SETS_REFRESH();

	TEST3_SETUP(usec);
	ret = select(inet_sock + 1, &readfds, &writefds, &exceptfds, &tv);
	TEST3_TESTS(select);

	TEST4_SETUP(usec);
	ret = select(inet_sock + 1, &readfds, &writefds, &exceptfds, &tv);
	TEST4_TESTS(select);

	TEST5_SETUP(usec);
	ret = select(inet_sock + 1, &readfds, &writefds, &exceptfds, &tv);
	TEST567_TESTS(select);

	TEST6_SETUP(usec);
	ret = select(inet_sock2 + 1, &readfds, &writefds, &exceptfds, &tv);
	TEST567_TESTS(select);

	TEST7_SETUP(usec);
	ret = select(inet_sock2 + 1, &readfds, &writefds, &exceptfds, &tv);
	TEST567_TESTS(select);


error:
	if (inet_sock >= 0) {
		close(inet_sock);
	}
	if (inet_sock2 >= 0) {
		close(inet_sock);
	}
	if (inet_sock3 >= 0) {
		close(inet_sock);
	}
	return;
}

static void test_pselect(void)
{
	int pipe_fds[2], ret;
	int inet_sock = -1, inet_sock2 = -1, inet_sock3 = -1;
	struct sockaddr_in addrv4;
	const char *ip = "93.95.227.222";
	fd_set readfds, writefds, exceptfds;
	struct timespec tv;
	time_t now;

	ret = pipe(pipe_fds);
	if (ret < 0) {
		fail("Unable to create pipe");
		goto error;
	}

	/* This test is to see if we go through the libc or not. */
	ret = getpeername(pipe_fds[0], NULL, NULL);
	ok(ret == -1 && errno == ENOTSOCK, "Invalid socket fd");

        TEST1_SETUP(nsec);

	/* Now let's see if we return immediately and successfully */
	ret = pselect(pipe_fds[1] + 1, &readfds, &writefds, &exceptfds, &tv, NULL);
	TEST1_TESTS(pselect);

	TEST2_SETUP(nsec);
	ret = pselect(pipe_fds[1] + 1, &readfds, &writefds, &exceptfds, &tv, NULL);
	TEST2_TESTS(pselect);

	PIPE_SETS_REFRESH();

	TEST3_SETUP(nsec);
	ret = pselect(inet_sock + 1, &readfds, &writefds, &exceptfds, &tv, NULL);
	TEST3_TESTS(pselect);

	TEST4_SETUP(nsec);
	ret = pselect(inet_sock + 1, &readfds, &writefds, &exceptfds, &tv, NULL);
	TEST4_TESTS(pselect);

	TEST5_SETUP(nsec);
	ret = pselect(inet_sock + 1, &readfds, &writefds, &exceptfds, &tv, NULL);
	TEST567_TESTS(pselect);

	TEST6_SETUP(nsec);
	ret = pselect(inet_sock2 + 1, &readfds, &writefds, &exceptfds, &tv, NULL);
	TEST567_TESTS(pselect);

	TEST7_SETUP(nsec);
	ret = pselect(inet_sock2 + 1, &readfds, &writefds, &exceptfds, &tv, NULL);
	TEST567_TESTS(pselect);


error:
	if (inet_sock >= 0) {
		close(inet_sock);
	}
	if (inet_sock2 >= 0) {
		close(inet_sock);
	}
	if (inet_sock3 >= 0) {
		close(inet_sock);
	}
	return;
}

int main(int argc, char **argv)
{
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS*2);

	test_select();
	test_pselect();

    return 0;
}
