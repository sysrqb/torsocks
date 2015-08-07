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
#include <unistd.h>

#include <lib/torsocks.h>
#include <poll.h>

#include <tap/tap.h>

#define NUM_TESTS 38

#define TEST1_SETUP()						\
	do {							\
		fds[0].fd = pipe_fds[0];			\
		fds[0].events = POLLIN | POLLOUT | POLLERR;	\
		fds[1].fd = pipe_fds[1];			\
		fds[1].events = POLLIN | POLLOUT | POLLERR;	\
		now = time(NULL);				\
	} while (0)

#define TEST1_TESTS(vers)				\
	do {						\
		ok(ret == 1 && (time(NULL) - now) < 2,	\
		   #vers " returned without error");	\
		ok(!(fds[0].revents & POLLOUT),		\
		   "Read end of pipe blocks on write"); \
		ok(!(fds[0].revents & POLLIN),		\
		   "Read end of pipe blocks on read");	\
		ok(fds[1].revents & POLLOUT,		\
		   "Write end of pipe is writable");	\
		ok(!(fds[1].revents & POLLIN),		\
		   "Write end of pipe blocks on read");	\
	} while (0)

#define TEST2_SETUP()							\
	do {								\
		ret = write(pipe_fds[1], "test", strlen("test"));	\
		ok(ret != 1, "Wrote into pipe.");			\
		now = time(NULL);					\
	} while (0)

#define TEST2_TESTS(vers)					\
	do {							\
		ok(ret == 2 && (time(NULL) - now) < 2,		\
		   #vers " returned without error");		\
		ok(!(fds[0].revents & POLLOUT),			\
		   "Read end of pipe blocks on write");		\
		ok(fds[0].revents & POLLIN,			\
		   "Read end of pipe blocks on read");		\
		ok(fds[1].revents & POLLOUT,			\
		   "Write end of pipe is writable");		\
		ok(!(fds[1].revents & POLLIN),			\
		   "Write end of pipe blocks on read");		\
	} while (0)

#define PIPE_SETS_REFRESH()		\
	do {				\
		close(pipe_fds[0]);	\
		close(pipe_fds[1]);	\
		pipe_fds[0] = -1;	\
		pipe_fds[1] = -1;	\
		fds[0].fd = 0;		\
		fds[0].events = 0;	\
		fds[1].fd = 0;		\
		fds[1].events = 0;	\
	} while (0)

#define TEST3_SETUP()						\
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
		 * the wrapper. */				\
		addrv4.sin_family = AF_INET;			\
		addrv4.sin_port = htons(443);			\
		inet_pton(addrv4.sin_family, ip,		\
			  &addrv4.sin_addr);			\
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
		fds[0].fd = inet_sock;				\
		fds[0].events = POLLIN;				\
		now = time(NULL);				\
	} while (0)

#define TEST3_TESTS(vers)					\
	do {							\
		ok(ret == 0 && (time(NULL) - now) < 2,		\
		   #vers " with inet socket returned without "	\
		   "error");					\
		ok(!(fds[0].revents & POLLIN),			\
		   "inet socket has no data needing reading");	\
		ok(!(fds[0].revents & POLLOUT),			\
		   "inet socket not considered writable");	\
		ok(!(fds[0].revents & POLLERR),			\
		   "inet socket not in exception state");	\
	} while (0)

#define TEST4_SETUP()				\
	do {					\
		fds[0].events = POLLOUT;	\
		now = time(NULL);		\
	} while (0)

#define TEST4_TESTS(vers)					\
	do {							\
		ok(ret != -1 && (time(NULL) - now) < 2,		\
		   #vers " with inet socket returned without "	\
		   "error");					\
		ok(!(fds[0].revents & POLLIN),			\
		   "inet socket has no data needing reading");	\
		ok(fds[0].revents & POLLOUT,			\
		   "inet socket is writable");			\
		ok(!(fds[0].revents & POLLERR),			\
		   "inet socket not in exception state");	\
	} while (0)

#define TEST5_SETUP()				\
	do {					\
		fds[0].events = POLLERR;	\
		now = time(NULL);		\
	} while (0)

#define TEST567_TESTS(vers)					\
	do {							\
                ok(ret != -1 && (time(NULL) - now) < 2,		\
                   #vers " with inet socket returned without "	\
                   "error");					\
                ok(!(fds[0].revents & POLLIN),			\
                   "inet socket has no data needing reading");	\
                ok(!(fds[0].revents & POLLOUT),			\
                   "inet socket is not considered writable");	\
                ok(!(fds[0].revents & POLLERR),			\
                   "inet socket not in exception state");	\
	} while (0)


#define TEST6_SETUP()							\
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
		fds[0].fd = inet_sock;					\
		fds[0].events = POLLIN;					\
		fds[1].fd = inet_sock2;					\
		fds[1].events = POLLIN;					\
		now = time(NULL);					\
	} while (0)

#define TEST7_SETUP()					\
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
		fds[0].fd = inet_sock;					\
		fds[0].events = POLLIN;					\
		fds[1].fd = inet_sock2;					\
		fds[1].events = POLLIN;					\
		now = time(NULL);					\
	} while (0)


static void test_poll(void)
{
	int pipe_fds[2], ret;
	int inet_sock = -1, inet_sock2 = -1, inet_sock3 = -1;
	struct sockaddr_in addrv4;
	const char *ip = "93.95.227.222";
	struct pollfd fds[3];
	time_t now;

	ret = pipe(pipe_fds);
	if (ret < 0) {
		fail("Unable to create pipe");
		goto error;
	}

	/* This test is to see if we go through the libc or not. */
	ret = getpeername(pipe_fds[0], NULL, NULL);
	ok(ret == -1 && errno == ENOTSOCK, "Invalid socket fd");

	TEST1_SETUP();
	/* Now let's see if we return immediately and successfully */
	ret = poll(fds, 2, 0);
	TEST1_TESTS(poll);

	TEST2_SETUP();
	ret = poll(fds, 2, 0);
	TEST2_TESTS(poll);

	PIPE_SETS_REFRESH();

	TEST3_SETUP();
	ret = poll(fds, 1, 0);
	TEST3_TESTS(poll);

	TEST4_SETUP();
	ret = poll(fds, 1, 0);
	TEST4_TESTS(poll);

	TEST5_SETUP();
	ret = poll(fds, 1, 0);
	TEST567_TESTS(poll);

	TEST6_SETUP();
	ret = poll(fds, 2, 0);
	TEST567_TESTS(poll);

	TEST7_SETUP();
	ret = poll(fds, 2, 0);
	TEST567_TESTS(poll);

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
	plan_tests(NUM_TESTS);

	test_poll();

    return 0;
}
