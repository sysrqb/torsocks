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

#include <sys/types.h>
#include <unistd.h>

#include <lib/torsocks.h>

#include <tap/tap.h>

#if (defined(__linux__))

#define NUM_TESTS 35

#define TEST1_SETUP(pfd)						\
	do {							\
		event.events = EPOLLIN | EPOLLOUT | POLLERR;	\
		event.data.fd = pfd;				\
		now = time(NULL);				\
	} while (0)

#define TEST1_TESTS(side, fd)						\
	do {								\
		ok(ret == 0 && (time(NULL) - now) < 2,			\
		   "1: Added " #side " %d for IN, OUT, ERR events,", fd);	\
	} while (0)

#define TEST259_SETUP()							\
	do {								\
		now = time(NULL);					\
	} while (0)

#define TEST2_TESTS(vers)					\
	do {							\
		ok(ret != -1 && (time(NULL) - now) < 2,		\
		   "2: " #vers " returned successfully");		\
		ok(ret == 1 &&					\
		   events[0].data.fd == pipe_fds[1] &&		\
		   !!(events[0].events & EPOLLOUT),		\
		   "2: Write-end is ready for writing");		\
	} while (0)

#define TEST3_SETUP()							\
	do {								\
		ret = write(pipe_fds[1], "test", strlen("test"));	\
		ok(ret != 1, "3: Wrote into pipe.");			\
		now = time(NULL);					\
	} while (0)

#define TEST3_TESTS(vers)					\
	do {							\
		int got_read = 0, got_write = 0;		\
		ok(ret != -1 && (time(NULL) - now) < 2,		\
		   "3: " #vers " returned successfully");		\
		ok(ret == 2,					\
		   "3: Two sockets are ready for action"); 	\
		if ((events[0].data.fd == pipe_fds[1]) &&	\
		    (events[0].events & EPOLLOUT)) {		\
		   ok(!(events[0].events & EPOLLIN),		\
		      "3: Write-end is ready for writing");	\
			got_write = 1;				\
		}						\
		if ((events[0].data.fd == pipe_fds[0]) &&	\
		    (events[0].events & EPOLLIN)) {		\
		   ok(!(events[0].events & EPOLLOUT),		\
		      "3: Read-end is ready for writing");		\
			got_read = 1;				\
		}						\
		if ((events[1].data.fd == pipe_fds[1]) &&	\
		    (events[1].events & EPOLLOUT)) {		\
		   ok(!(events[1].events & EPOLLIN),		\
		      "3: Write-end is ready for writing");	\
			got_write = 1;				\
		}						\
		if ((events[1].data.fd == pipe_fds[0]) &&	\
		    (events[1].events & EPOLLIN)) {		\
		   ok(!(events[1].events & EPOLLOUT),		\
		      "3: Read-end is ready for writing");		\
			got_read = 1;				\
		}						\
		ok(got_read == 1 && got_write == 1,		\
		   "3: Read and write ends are ready");		\
	} while (0)

#define PIPE_EPOLL_REFRESH()		\
	do {				\
		close(pipe_fds[0]);	\
		close(pipe_fds[1]);	\
		pipe_fds[0] = -1;	\
		pipe_fds[1] = -1;	\
		close(epfd);		\
	} while (0)

#define TEST4_SETUP()						\
	do {							\
		/* Create inet socket. */			\
		inet_sock = socket(AF_INET, SOCK_STREAM, 0);	\
		ok(inet_sock >= 0, "4: Inet socket created");	\
								\
		/* Create another inet socket. */		\
		inet_sock2 = socket(AF_INET, SOCK_STREAM, 0);	\
		ok(inet_sock2 >= 0, "4: Inet socket 2 created");	\
								\
		/* Create another inet socket. */		\
		inet_sock3 = socket(AF_INET, SOCK_STREAM, 0);	\
		ok(inet_sock3 >= 0, "4: Inet socket 3 created");	\
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
			fail("4: Unable to connect to %s", ip);	\
			goto error;				\
		}						\
								\
		event.events = EPOLLIN | EPOLLOUT | POLLERR;	\
		event.data.fd = inet_sock;			\
		now = time(NULL);				\
	} while (0)

#define TEST4678_TESTS(fd)						\
	do {								\
		ok(ret == 0 && (time(NULL) - now) < 2,			\
		   "467: Added inet socket %d for IN, OUT, ERR events, %d, %s",	\
		   fd, getpid(), strerror(errno));							\
	} while (0)

#define TEST5_TESTS(vers)					\
	do {							\
		ok(ret == 1 && (time(NULL) - now) < 2,		\
		   "5: " #vers " with inet socket returned without "	\
		   "error");					\
		ok(!(events[0].events & POLLIN),		\
		   "5: inet socket has no data needing reading");	\
		ok(events[0].events & POLLOUT,			\
		   "5: inet socket is writable");			\
		ok(!(events[0].events & POLLERR),		\
		   "5: inet socket not in exception state");	\
	} while (0)


#define TEST6_SETUP()							\
	do {								\
		ret = connect(inet_sock2, (struct sockaddr *) &addrv4,	\
			      sizeof(addrv4));				\
		if (ret < 0) {						\
			fail("6: Unable to connect to %s", ip);		\
			goto error;					\
		}							\
									\
		ret = connect(inet_sock3, (struct sockaddr *) &addrv4,	\
			      sizeof(addrv4));				\
		if (ret < 0) {						\
			fail("6: Unable to connect to %s", ip);		\
			goto error;					\
		}							\
									\
	} while (0)

#define ADD_FD(sfd)						\
	do {							\
		event.events = EPOLLIN | EPOLLOUT | POLLERR;	\
		event.data.fd = sfd;				\
		now = time(NULL);				\
	} while (0)
	
#define DEL_FD_FROM_EPFD(fd, epfd)						\
	do {									\
		ret = epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);			\
		ok(ret == 0, "Successfully deleted %d from %d", fd, epfd);	\
	} while (0)

#define TEST7_SETUP()							\
	do {								\
		close(inet_sock3);					\
		close(inet_sock2);					\
									\
		ret = pipe(pipe_fds);					\
		if (ret < 0) {						\
			fail("7: Unable to create pipe 2");		\
			goto error;					\
		}							\
		ok(pipe_fds[0] > 0 && pipe_fds[1] > 0,			\
		   "7: new pipe created");					\
									\
		/* Create another inet socket. */			\
		inet_sock2 = socket(AF_INET, SOCK_STREAM, 0);		\
		ok(inet_sock2 >= 0, "7: Inet socket 2 created, %d",	\
				    inet_sock2);			\
									\
		/* Create another inet socket. */			\
		inet_sock3 = socket(AF_INET, SOCK_STREAM, 0);		\
		ok(inet_sock3 >= 0, "7: Inet socket 3 created, %d",	\
				     inet_sock3);			\
									\
		ret = connect(inet_sock2, (struct sockaddr *) &addrv4,	\
			      sizeof(addrv4));				\
		if (ret < 0) {						\
			fail("7: Unable to connect to %s", ip);		\
			goto error;					\
		}							\
									\
		ret = connect(inet_sock3, (struct sockaddr *) &addrv4,	\
			      sizeof(addrv4));				\
		if (ret < 0) {						\
			fail("7: Unable to connect to %s", ip);		\
			goto error;					\
		}							\
									\
		now = time(NULL);					\
	} while (0)

#define TEST9_TESTS(vers)					\
	do {							\
		int got_write = 0;				\
		ok(ret != -1 && (time(NULL) - now) < 2,		\
		   "8: " #vers " returned successfully");		\
		ok(ret == 3,					\
		   "8: Three (%d) sockets are ready for action, "	\
		   "%d, %d and %d", ret, events[0].data.fd,		\
		   events[1].data.fd, events[2].data.fd); 				\
		if ((events[0].data.fd == inet_sock) &&		\
		    (events[0].events & EPOLLOUT)) {		\
		   ok(!(events[0].events & EPOLLIN),		\
		      "8: inet_sock %d is ready for writing",	\
		      events[0].data.fd);			\
			got_write++;				\
		} else if ((events[0].data.fd == inet_sock2) &&	\
		    (events[0].events & EPOLLOUT)) {		\
		   ok(!(events[0].events & EPOLLIN),		\
		      "8: inet_sock %d is ready for writing",	\
		      events[0].data.fd);			\
			got_write++;				\
		} else if ((events[0].data.fd == inet_sock3) &&	\
		    (events[0].events & EPOLLOUT)) {		\
		   ok(!(events[0].events & EPOLLIN),		\
		      "8: inet_sock %d is ready for writing",	\
		      events[0].data.fd);			\
			got_write++;				\
		}						\
		if ((events[1].data.fd == inet_sock) &&		\
		    (events[1].events & EPOLLOUT)) {		\
		   ok(!(events[1].events & EPOLLIN),		\
		      "8: inet_sock %d is ready for writing",	\
		      events[1].data.fd);			\
			got_write++;				\
		} else if ((events[1].data.fd == inet_sock2) &&	\
		    (events[1].events & EPOLLOUT)) {		\
		   ok(!(events[1].events & EPOLLIN),		\
		      "8: inet_sock %d is ready for writing",	\
		      events[1].data.fd);			\
			got_write++;				\
		} else if ((events[1].data.fd == inet_sock3) &&	\
		    (events[1].events & EPOLLOUT)) {		\
		   ok(!(events[1].events & EPOLLIN),		\
		      "8: inet_sock %d is ready for writing",	\
		      events[1].data.fd);			\
			got_write++;				\
		}						\
		if ((events[2].data.fd == inet_sock) &&		\
		    (events[2].events & EPOLLOUT)) {		\
		   ok(!(events[2].events & EPOLLIN),		\
		      "8: inet_sock %d is ready for writing",	\
		      events[2].data.fd);			\
			got_write++;				\
		} else if ((events[2].data.fd == inet_sock2) &&	\
		    (events[2].events & EPOLLOUT)) {		\
		   ok(!(events[2].events & EPOLLIN),		\
		      "8: inet_sock %d is ready for writing",	\
		      events[2].data.fd);			\
			got_write++;				\
		} else if ((events[2].data.fd == inet_sock3) &&	\
		    (events[2].events & EPOLLOUT)) {		\
		   ok(!(events[2].events & EPOLLIN),		\
		      "8: inet_sock %d is ready for writing",	\
		      events[2].data.fd);			\
			got_write++;				\
		}						\
		ok(got_write == 3,				\
		   "8: All sockets are ready for writing");	\
	} while (0)


static void test_epoll_create_wait(void)
{
	int pipe_fds[2], ret;
	int epfd, inet_sock = -1, inet_sock2 = -1, inet_sock3 = -1;
	struct sockaddr_in addrv4;
	const char *ip = "93.95.227.222";
	struct epoll_event event, events[3];
	time_t now;

	epfd = epoll_create(1);
	ok(epfd > 1, "1: Created new epoll fd %d", epfd);

	ret = pipe(pipe_fds);
	if (ret < 0) {
		fail("1: Unable to create pipe");
		goto error;
	}

	TEST1_SETUP(pipe_fds[0]);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_fds[0], &event);
	TEST1_TESTS(read-side, pipe_fds[0]);

	TEST1_SETUP(pipe_fds[1]);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_fds[1], &event);
	TEST1_TESTS(write-side, pipe_fds[1]);

	TEST259_SETUP();
	ret = epoll_wait(epfd, events, 3, 0);
	TEST2_TESTS(epoll_wait);

	TEST3_SETUP();
	ret = epoll_wait(epfd, events, 3, 0);
	TEST3_TESTS(epoll_wait);

	PIPE_EPOLL_REFRESH();

	epfd = epoll_create(1);
	ok(epfd > 1, "4: Created new epoll fd %d", epfd);

	TEST4_SETUP();
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, inet_sock, &event);
	TEST4678_TESTS(inet_sock);

	TEST259_SETUP();
	ret = epoll_wait(epfd, events, 3, 0);
	TEST5_TESTS(epoll_wait);

	TEST6_SETUP();
	ADD_FD(inet_sock2);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, inet_sock2, &event);
	TEST4678_TESTS(inet_sock2);

	ADD_FD(inet_sock3);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, inet_sock3, &event);
	TEST4678_TESTS(inet_sock3);

	DEL_FD_FROM_EPFD(inet_sock3, epfd);
	DEL_FD_FROM_EPFD(inet_sock2, epfd);

	TEST7_SETUP();
	ADD_FD(inet_sock2);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, inet_sock2, &event);
	TEST4678_TESTS(inet_sock2);

	TEST259_SETUP();

	ADD_FD(inet_sock3);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, inet_sock3, &event);
	TEST4678_TESTS(inet_sock3);

	TEST259_SETUP();
	ret = epoll_wait(epfd, events, 3, 0);
	TEST9_TESTS(epoll_wait);

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
	if (epfd >= 0) {
		close(epfd);
	}
	return;
}

static void test_epoll_create1_pwait(void)
{
	int pipe_fds[2], ret;
	int epfd, inet_sock = -1, inet_sock2 = -1, inet_sock3 = -1;
	struct sockaddr_in addrv4;
	const char *ip = "93.95.227.222";
	struct epoll_event event, events[3];
	time_t now;

	epfd = epoll_create1(0);
	ok(epfd > 1, "1: Created new epoll fd %d", epfd);

	ret = pipe(pipe_fds);
	if (ret < 0) {
		fail("1: Unable to create pipe");
		goto error;
	}

	TEST1_SETUP(pipe_fds[0]);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_fds[0], &event);
	TEST1_TESTS(read-side, pipe_fds[0]);

	TEST1_SETUP(pipe_fds[1]);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_fds[1], &event);
	TEST1_TESTS(write-side, pipe_fds[1]);

	TEST259_SETUP();
	ret = epoll_pwait(epfd, events, 3, 0, NULL);
	TEST2_TESTS(epoll_pwait);

	TEST3_SETUP();
	ret = epoll_pwait(epfd, events, 3, 0, NULL);
	TEST3_TESTS(epoll_pwait);

	PIPE_EPOLL_REFRESH();

	epfd = epoll_create1(0);
	ok(epfd > 1, "4: Created new epoll fd %d", epfd);

	TEST4_SETUP();
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, inet_sock, &event);
	TEST4678_TESTS(inet_sock);

	TEST259_SETUP();
	ret = epoll_pwait(epfd, events, 3, 0, NULL);
	TEST5_TESTS(epoll_pwait);

	TEST6_SETUP();
	ADD_FD(inet_sock2);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, inet_sock2, &event);
	TEST4678_TESTS(inet_sock2);

	ADD_FD(inet_sock3);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, inet_sock3, &event);
	TEST4678_TESTS(inet_sock3);

	DEL_FD_FROM_EPFD(inet_sock3, epfd);
	DEL_FD_FROM_EPFD(inet_sock2, epfd);

	TEST7_SETUP();
	ADD_FD(inet_sock2);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, inet_sock2, &event);
	TEST4678_TESTS(inet_sock2);

	TEST259_SETUP();

	ADD_FD(inet_sock3);
	ret = epoll_ctl(epfd, EPOLL_CTL_ADD, inet_sock3, &event);
	TEST4678_TESTS(inet_sock3);

	TEST259_SETUP();
	ret = epoll_pwait(epfd, events, 3, 0, NULL);
	TEST9_TESTS(epoll_pwait);

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
	if (epfd >= 0) {
		close(epfd);
	}
	return;
}
#endif // __linux__

int main(int argc, char **argv)
{
#if (defined(__linux__))
	/* Libtap call for the number of tests planned. */
	plan_tests(NUM_TESTS*2);

	test_epoll_create_wait();
	test_epoll_create1_pwait();
#else
	skip(1, "Skipping on unsupported platform.");
#endif // __linux__

    return 0;
}
