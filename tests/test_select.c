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

#define NUM_TESTS 21

static void test_select(void)
{
	int pipe_fds[2], ret, inet_sock = -1;
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

	FD_SET(pipe_fds[0], &readfds);
	FD_SET(pipe_fds[1], &readfds);
	FD_SET(pipe_fds[0], &writefds);
	FD_SET(pipe_fds[1], &writefds);
	FD_SET(pipe_fds[0], &exceptfds);
	FD_SET(pipe_fds[1], &exceptfds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	now = time(NULL);

	/* Now let's see if we return immediately and successfully */
	ret = select(pipe_fds[1] + 1, &readfds, &writefds, &exceptfds, &tv);
	ok(ret != -1 && (time(NULL) - now) < 2, "Select returned without error");
	ok(!FD_ISSET(pipe_fds[0], &readfds), "Read end of pipe has no data");
	ok(FD_ISSET(pipe_fds[1], &writefds), "Write end of pipe is writable");

	ret = write(pipe_fds[1], "test", strlen("test"));
	ok(ret != 1, "Write failed on pipe.");
	FD_SET(pipe_fds[0], &readfds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	now = time(NULL);
	ret = select(pipe_fds[1] + 1, &readfds, &writefds, &exceptfds, &tv);
	ok(ret != -1 && (time(NULL) - now) < 2, "Select returned without error, again");
	ok(FD_ISSET(pipe_fds[0], &readfds), "Read end of pipe has data");
	ok(FD_ISSET(pipe_fds[1], &writefds), "Write end of pipe is still writable");

	close(pipe_fds[0]);
	close(pipe_fds[1]);
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);

	/* Create inet socket. */
	inet_sock = socket(AF_INET, SOCK_STREAM, 0);
	ok(inet_sock >= 0, "Inet socket created");

	/* Connect socket through Tor so we can test the wrapper. */
	addrv4.sin_family = AF_INET;
	addrv4.sin_port = htons(443);
	inet_pton(addrv4.sin_family, ip, &addrv4.sin_addr);
	memset(addrv4.sin_zero, 0, sizeof(addrv4.sin_zero));

	ret = connect(inet_sock, (struct sockaddr *) &addrv4, sizeof(addrv4));
	if (ret < 0) {
		fail("Unable to connect to %s", ip);
		goto error;
	}

	FD_SET(inet_sock, &readfds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	now = time(NULL);
	ret = select(inet_sock + 1, &readfds, &writefds, &exceptfds, &tv);
	ok(ret != -1 && (time(NULL) - now) < 2, "Select with inet socket returned without error");
	ok(!FD_ISSET(inet_sock, &readfds), "inet socket has no data for reading");
	ok(!FD_ISSET(inet_sock, &writefds), "inet socket not in writable fd set");
	ok(!FD_ISSET(inet_sock, &exceptfds), "inet socket not in exception fd set");

	FD_ZERO(&readfds);
	FD_SET(inet_sock, &writefds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	now = time(NULL);
	ret = select(inet_sock + 1, &readfds, &writefds, &exceptfds, &tv);
	ok(ret != -1 && (time(NULL) - now) < 2, "Select with inet socket returned without error");
	ok(!FD_ISSET(inet_sock, &readfds), "inet socket has no data for reading");
	ok(FD_ISSET(inet_sock, &writefds), "inet socket not in writable fd set");
	ok(!FD_ISSET(inet_sock, &exceptfds), "inet socket not in exception fd set");

	FD_ZERO(&writefds);
	FD_SET(inet_sock, &exceptfds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	now = time(NULL);
	ret = select(inet_sock + 1, &readfds, &writefds, &exceptfds, &tv);
	ok(ret != -1 && (time(NULL) - now) < 2, "Select with inet socket returned without error");
	ok(!FD_ISSET(inet_sock, &readfds), "inet socket has no data for reading");
	ok(!FD_ISSET(inet_sock, &writefds), "inet socket not in writable fd set");
	ok(!FD_ISSET(inet_sock, &exceptfds), "inet socket has no exception");

error:
	if (inet_sock >= 0) {
		close(inet_sock);
	}
	return;
}

int main(int argc, char **argv)
{
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS);

	test_select();

    return 0;
}
