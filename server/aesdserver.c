#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

const char temp_filename[] = "/var/tmp/aesdsocketdata";

int sockfd;
int sockfd_new;
int logfd;
struct addrinfo *res;
struct packet_buffer pbuf;

// container to hold memory for packet buffer
struct packet_buffer {
    char *data;
    size_t ptr;
    size_t size;
};

static void cleanup() {
    if (res) {
        freeaddrinfo(res);
    }
    if (sockfd) {
        close(sockfd);
    }
    if (sockfd_new) {
        close(sockfd_new);
    }
    if (logfd) {
        close(logfd);
    }
    free(pbuf.data);
    // delete the temp file
    remove(temp_filename);
}

void pbuf_alloc(struct packet_buffer *buf) {
    if (!buf->data) {
        buf->data = (char*)malloc(1024);
        buf->size = 1024;
    } else {
        // if we need more memory, double it
        buf->data = realloc(buf->data, buf->size*2);
        buf->size *= 2;
    }
    if (buf->data == NULL) {
        perror("malloc");
        cleanup();
        exit(1);
    }
}

void handle_signal(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        syslog(LOG_INFO, "Caught signal, exiting");
        cleanup();
        exit(1);
    }
}

void write_to_file(int writefd, const void* buf, size_t write_size) {
    int bytes_written = write(writefd, buf, write_size);
    if (bytes_written == -1) {
        perror("write");
        cleanup();
        exit(1);
    } else if (bytes_written < write_size) {
        printf("Attempted to write %ld bytes, only wrote %d\n", write_size, bytes_written);
    }
}

void send_temp_file(int sockfd, int tempfd) {
    int pos = lseek(tempfd, 0, SEEK_SET); // seek to beginning of file
    if (pos == -1) {
        perror("lseek");
        cleanup();
        exit(1);
    }

    char tempbuf[1024];
    size_t bytes_read = read(tempfd, tempbuf, sizeof(tempbuf));
    while (bytes_read != 0) {
        if (bytes_read == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("read");
            cleanup();
            exit(1);
        }

        write_to_file(sockfd, tempbuf, bytes_read);
        bytes_read = read(tempfd, tempbuf, sizeof(tempbuf));
    }
}

int main(int argc, char **argv) {
    // set up signal handlers
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = handle_signal;
    if (sigaction(SIGTERM, &sa, NULL) != 0) {
        printf("Error %d (%s) registering for SIGTERM\n", errno, strerror(errno));
        cleanup();
        exit(1);
    }
    if (sigaction(SIGINT, &sa, NULL) != 0) {
        printf("Error %d (%s) registering for SIGTERM\n", errno, strerror(errno));
        cleanup();
        exit(1);
    }

    // check for daemon option
    int is_daemon = 0;
    int c;
    while ((c = getopt(argc, argv, "d")) != -1) {
        switch (c) {
            case 'd':
                is_daemon = 1;
                break;
            default:
                exit(1);
        }
    }

    printf("is daemon: %d\n", is_daemon);

    // get sockaddr
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    //struct addrinfo *res;

    int status;
    if ((status = getaddrinfo(NULL, "9000", &hints, &res)) != 0) {
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(1);
    }

    if (res == NULL) {
        fprintf(stderr, "Error: res is NULL\n");
        exit(1);
    }

    // note: should ideally walk through the res linked list rather than just using
    // the first element

    // open a socket
    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
        perror("socket");
        cleanup();
        exit(1);
    }

    // bind
    if ((status = bind(sockfd, res->ai_addr, res->ai_addrlen)) != 0) {
        perror("bind");
        cleanup();
        exit(1);
    }

    // if running as a daemon, do that setup now
    if (is_daemon) {
        pid_t pid;

        pid = fork();
        if (pid == -1) {
            perror("fork");
            cleanup();
            exit(1);
        } else if (pid != 0) {
            cleanup();
            exit(0);
        }

        // create a new session and process group
        if (setsid() == -1) {
            perror("setsid");
            cleanup();
            exit(-1);
        }

        // set the working directory to root dir
        if (chdir("/") == -1) {
            cleanup();
            perror("chdir");
        }

        // normally, we would close all open files next, but in this program we
        // need to use them

        // redirect fds to /dev/null
        open("/dev/null", O_RDWR);
        dup(0);
        dup(0);
    }

    // open file for appending
    int wrflags = O_RDWR | O_APPEND | O_CREAT;
    logfd = open(temp_filename, wrflags); 
    if (logfd == -1) {
        perror("open");
        cleanup();
        exit(1);
    }

    // now receive data from the interface
    memset(&pbuf, 0, sizeof(struct packet_buffer));
    pbuf_alloc(&pbuf);
    
    while (1) {
        // listen
        if ((status = listen(sockfd, 1)) != 0) {
            perror("listen");
            cleanup();
            exit(1);
        }

        // accept
        struct sockaddr addr_conn;
        socklen_t addr_conn_len = sizeof(addr_conn);
        sockfd_new = accept(sockfd, &addr_conn, &addr_conn_len);
        if (sockfd_new == -1) {
            perror("accept");
            cleanup();
            exit(1);
        }

        // log the connection
        char addr_conn_str [INET_ADDRSTRLEN];
        struct sockaddr_in *sin = (struct sockaddr_in *)&addr_conn;
        inet_ntop(AF_INET, &(sin->sin_addr), addr_conn_str, INET_ADDRSTRLEN);
        syslog(LOG_INFO, "Accepted connection from %s", addr_conn_str);

        char *sop = pbuf.data;
        while (1) {
            // read bytes from network
            int remaining = pbuf.size - pbuf.ptr;
            int bytes_recv = recv(sockfd_new, pbuf.data + pbuf.ptr, remaining - 1, 0);
            if (bytes_recv == -1) {
                perror("recv");
                cleanup();
                exit(1);
            } else if (bytes_recv == 0) {
                syslog(LOG_DEBUG, "connection terminated\n");
                break;
            } else {
                // separate into packets demarcated by '\n'
                char *last = pbuf.data + pbuf.ptr + bytes_recv;
                *last = '\0'; // make it a null-terminated string
                char *eop = strchr(sop, '\n');
                while (eop != NULL) {
                    write_to_file(logfd, sop, eop + 1 - sop);
                    send_temp_file(sockfd_new, logfd);
                    sop = eop + 1;
                    eop = strchr(sop, '\n');
                }
                if (sop != last) {
                    pbuf.ptr = last - pbuf.data;
                } else {
                    pbuf.ptr = 0;
                    sop = pbuf.data;
                }
                if (pbuf.ptr >= pbuf.size - 1) {
                    // need to increase the size
                    char *pbuf_data_old = pbuf.data;
                    pbuf_alloc(&pbuf);
                    // realloc could change the base pointer, need to adjust sop in that case
                    if (pbuf.data != pbuf_data_old) {
                        sop = pbuf.data + (sop - pbuf_data_old);
                    }
                }
            }
        }
    }

    cleanup();

    return 0;
}
