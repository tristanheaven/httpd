/*
 *  Copyright (C) 2013 Tristan Heaven <tristanheaven@gmail.com>
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty.  In no event will the author(s) be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgment in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 *
 */

#define _GNU_SOURCE
#define _LARGEFILE_SOURCE 1
#define _LARGEFILE64_SOURCE 1
#define _FILE_OFFSET_BITS 64

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <time.h>

#define SERVER_NAME "useless-httpd"
#define SERVER_HTDOCS "htdocs"
#define SERVER_INDEX "index.html"
#define CLIENT_BUFSIZE 1024 // Number of bytes to accept from client
#define BIND_PORT 8080

// Supported HTTP status codes
#define HTTP_OK                         200
#define HTTP_BAD_REQUEST                400
#define HTTP_FORBIDDEN                  403
#define HTTP_NOT_FOUND                  404
#define HTTP_METHOD_NOT_ALLOWED         405
#define HTTP_REQUEST_ENTITY_TOO_LARGE   413
#define HTTP_IM_A_TEAPOT                418

#define INT_TO_POINTER(i) ((void *) (long int) (i))
#define POINTER_TO_INT(p) ((int) (long int) (p))

enum file_error_e {
	FILE_ERROR_INVALID = -1,
	FILE_ERROR_DENIED,
	FILE_ERROR_MISSING,
	FILE_ERROR_ISDIR,
	FILE_ERROR_NOTFILE,
};

struct file_s {
	int fd;
	char path[PATH_MAX + 1];
	struct stat stat_buf;
};

// Prepares a new TCP socket for binding
static int create_tcp_sock(void)
{
	int sockfd;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	// Allow address reuse
	int optval = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval,
		sizeof(optval)) < 0)
	{
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	return sockfd;
}

// Binds socket and listens for connections
static int new_listen_sock(void)
{
	const int sockfd = create_tcp_sock();

	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET; // IPv4
	addr.sin_port = htons(BIND_PORT); // Port number in network byte order
	addr.sin_addr.s_addr = INADDR_ANY; // Wildcard IP address

	// bind socket to address
	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	// listen on bound socket
	if (listen(sockfd, SOMAXCONN) < 0) {
		perror("listen");
		exit(EXIT_FAILURE);
	}

	printf("Listening for connections on port %d...\n", BIND_PORT);

	return sockfd;
}

// Construct HTTP Date string
static char *format_date(time_t s)
{
	char buf[1024];

	if (s == 0)
		s = time(NULL);

	struct tm tm = *gmtime(&s);
	strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S %Z", &tm);

	size_t len = strlen(buf) + 1;
	char *str = malloc(len);
	if (!str)
		exit(EXIT_FAILURE);

	strncpy(str, buf, len);

	return str;
}

// Write string to socket
static void write_string(const int sockfd, const char * const str)
{
	assert(str && *str);

//	printf("%s", str);

	if (write(sockfd, str, strlen(str)) < 0)
		perror("write");
}

// Sends HTTP headers to the client
static void send_server_headers(const int sockfd, const int code,
	struct file_s *file)
{
//	printf("SERVER SAYS:\n");

	// HTTP version
	write_string(sockfd, "HTTP/1.1 ");

	// Status code
	switch (code) {
		case HTTP_OK:
			write_string(sockfd, "200 OK\r\n");
			break;
		case HTTP_BAD_REQUEST:
			write_string(sockfd, "400 Bad Request\r\n");
			break;
		case HTTP_FORBIDDEN:
			write_string(sockfd, "403 Forbidden\r\n");
			break;
		case HTTP_NOT_FOUND:
			write_string(sockfd, "404 Not Found\r\n");
			break;
		case HTTP_METHOD_NOT_ALLOWED:
			write_string(sockfd,
				"405 Method Not Allowed\r\n"
				"Allow: GET\r\n");
			break;
		case HTTP_REQUEST_ENTITY_TOO_LARGE:
			write_string(sockfd, "413 Request Entity Too Large\r\n");
			break;
	}

	// Server software name
	write_string(sockfd, "Server: " SERVER_NAME "\r\n");

	// Current time
	write_string(sockfd, "Date: ");
	char *date = format_date(0);
	write_string(sockfd, date);
	free(date);
	write_string(sockfd, "\r\n");

	// File info
	if (code == HTTP_OK) {
		// File length
		char *newstr;
		if (asprintf(&newstr, "Content-Length: %zu\r\n",
			file->stat_buf.st_size) < 0)
		{
			fprintf(stderr, "asprintf failed");
			exit(EXIT_FAILURE);
		}
		write_string(sockfd, newstr);
		free(newstr);

		// File mtime
		write_string(sockfd, "Last-Modified: ");
		date = format_date(file->stat_buf.st_mtime);
		write_string(sockfd, date);
		free(date);
		write_string(sockfd, "\r\n");
	}

	// We don't support range requests
	write_string(sockfd, "Accept-Ranges: none\r\n");

	// We don't support keep-alive connections
	write_string(sockfd, "Connection: close\r\n");

	// End of headers
	write_string(sockfd, "\r\n");
}

// Sends the requested file
static void send_file(const int sockfd, struct file_s *file)
{
	assert(file);

	// Use Linux-specific function to write the whole file to
	// the socket in kernel space (it's fast)
	loff_t offset = 0;
	if (sendfile(sockfd, file->fd, &offset, file->stat_buf.st_size) < 0)
		perror("sendfile");
}

// Opens file and returns a complete file structure
static struct file_s *file_new(const char * const path,
	enum file_error_e *file_error)
{
	assert(path && *path);

	// Try to open the file...
	int fd;
	if ((fd = open(path, 0, O_RDONLY)) < 1) {
		int error = errno;
		fprintf(stderr, "%s: \"%s\"\n", path, strerror(errno));

		switch (error) {
			case EACCES:
				*file_error = FILE_ERROR_DENIED;
				break;
			case ENOENT:
			case EEXIST:
				*file_error = FILE_ERROR_MISSING;
				break;

			default:
				*file_error = FILE_ERROR_DENIED;
		}

		return NULL;
	}

	// Get file info
	struct stat stat_buf;
	if (fstat(fd, &stat_buf) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	// Is this a directory?
	if (S_ISDIR(stat_buf.st_mode)) {
		*file_error = FILE_ERROR_ISDIR;
		return NULL;
	}

	// Is this something other than a regular file?
	if (!S_ISREG(stat_buf.st_mode)) {
		*file_error = FILE_ERROR_NOTFILE;
		return NULL;
	}

	struct file_s *file = calloc(sizeof(struct file_s), 1);
	if (!file)
		exit(EXIT_FAILURE);

	file->fd = fd;
	snprintf(file->path, PATH_MAX, "%s", path);
	memcpy(&file->stat_buf, &stat_buf, sizeof(struct stat));

	return file;
}

// Frees file structure and closes the file
static void file_free(struct file_s *file)
{
	assert(file);

	close(file->fd);

	free(file);
}

// Returns the filename from a GET request
static bool parse_get_uri(const char * const in_buf, const size_t in_size,
	char *out_buf, const size_t out_size)
{
	assert(in_buf);
	assert(out_buf);
	assert(in_size > 0);
	assert(out_size > 0);

	// Attempt to disallow parent directory traversal
	if (strstr(in_buf, "/."))
		return false;

	memset(out_buf, 0, out_size);
	out_buf[0] = '.'; // We want to open files relative to the pwd

	// FIXME: Do some proper bounds checking
	// FIXME: urldecode

	// Find where the line ends so we can strip that part...
	char *str = strstr(in_buf, " HTTP/1.1\r\n");
	if (!str)
		str = strstr(in_buf, " HTTP/1.0\r\n");
	if (str) {
		// ...then skip the leading "GET ", leaving just the filename
		memcpy(out_buf + 1, in_buf + 4, str - in_buf - 4);
	}

	return (out_buf[1] != '\0');
}

// Thread function
static void *handle_request(void *data)
{
	const int sockfd = POINTER_TO_INT(data);
	int bytes = 0;
	struct file_s *file;
	enum file_error_e file_error = FILE_ERROR_INVALID;
	char buffer[CLIENT_BUFSIZE + 1];
	char path[PATH_MAX + 1];

	// Read client headers into buffer
	if ((bytes = read(sockfd, buffer, CLIENT_BUFSIZE + 1)) < 0) {
		perror("reading from socket");
		exit(EXIT_FAILURE);
	} else if (bytes > CLIENT_BUFSIZE) {
		// Client request was too long
		send_server_headers(sockfd, HTTP_REQUEST_ENTITY_TOO_LARGE, NULL);
		goto out;
	}

	buffer[bytes] = '\0';

//	printf("CLIENT SAYS:\n%s", buffer);

	// Only accept GET requests
	if (strncmp(buffer, "GET /", 5) != 0) {
		send_server_headers(sockfd, HTTP_METHOD_NOT_ALLOWED, NULL);
		goto out;
	}

	// Try to find a filename in the GET request
	if (!parse_get_uri(buffer, CLIENT_BUFSIZE, path, PATH_MAX)) {
		// Client is probably misbehaving
		send_server_headers(sockfd, HTTP_BAD_REQUEST, NULL);
		goto out;
	}

	for (;;) {
		// Try to send the requested file...
		printf("Sending %s\n", path);
		if ((file = file_new(path, &file_error))) {
			send_server_headers(sockfd, HTTP_OK, file);
			send_file(sockfd, file);
			file_free(file);
			break;
		} else if (file_error == FILE_ERROR_ISDIR) {
			// Try serving the default index file
			strcpy(path + strlen(path), "/" SERVER_INDEX);
			continue;
		} else {
			switch (file_error) {
				case FILE_ERROR_DENIED:
				case FILE_ERROR_NOTFILE:
					send_server_headers(sockfd, HTTP_FORBIDDEN, NULL);
					break;
				case FILE_ERROR_MISSING:
					send_server_headers(sockfd, HTTP_NOT_FOUND, NULL);
					break;
				default:
					assert(false);
			}
			break;
		}
	}

out:
	close(sockfd);
	return NULL;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	// SIGPIPE is raised when we try to write to a broken socket. Ignore it.
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	action.sa_handler = SIG_IGN;
	if (sigaction(SIGPIPE, &action, NULL) < 0) {
		perror("sigaction");
		return EXIT_FAILURE;
	}

	// Change to the public document root
	if (chdir(SERVER_HTDOCS) < 0) {
		perror("chdir(\"" SERVER_HTDOCS "\")");
		return EXIT_FAILURE;
	}

	// Start listening for connections
	const int sockfd = new_listen_sock();

	pthread_t thread;
	pthread_attr_t attr;

	if (pthread_attr_init(&attr) != 0) {
		fprintf(stderr, "pthead_attr_init failed\n");
		return EXIT_FAILURE;
	}

	if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
		fprintf(stderr, "pthread_attr_setdetachstate failed\n");
		return EXIT_FAILURE;
	}

	for (;;) {
		int newsockfd;

		// Blocks here until a new incoming connection is established
		if ((newsockfd = accept(sockfd, NULL, NULL)) < 0) {
			perror("accept");
			return EXIT_FAILURE;
		}

		// FIXME: Should be using a limited set of threads

		// Spawn a new thread to handle the request
		if (pthread_create(&thread, &attr, handle_request,
			INT_TO_POINTER(newsockfd)) != 0)
		{
			fprintf(stderr, "pthread_create failed\n");
			return EXIT_FAILURE;
		}
	}

	pthread_attr_destroy(&attr);
	close(sockfd);

	return EXIT_SUCCESS;
}
