#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>

#ifndef USE_AESD_CHAR_DEVICE
#define USE_AESD_CHAR_DEVICE 1
#endif

const char temp_filename[] = "/var/tmp/aesdsocketdata";
const char dev_driver[] = "/dev/aesdchar";

int sockfd;
int logfd;
int devfd;
pthread_mutex_t logfd_mutex;
struct addrinfo *res;

// container to hold memory for packet buffer
struct packet_buffer {
    char *data;
    size_t ptr;
    size_t size;
};

// SLIST.
typedef struct slist_data_s slist_data_t;
struct slist_data_s {
    pthread_t ptid;
    int sockfd;
    int complete;
    SLIST_ENTRY(slist_data_s) entries;
};

// set up linked list to store thread data
SLIST_HEAD(slisthead, slist_data_s) head;


static void cleanup() {
    if (res) {
        freeaddrinfo(res);
    }
    if (sockfd) {
        close(sockfd);
    }
    if (logfd) {
        close(logfd);
    }
    if (devfd) {
        close(devfd);
    }
    pthread_mutex_destroy(&logfd_mutex);
    // delete the temp file
    remove(temp_filename);
}

int pbuf_alloc(struct packet_buffer *buf) {
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
        return -1;
    }
    return 0;
}

void handle_signal(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        // cancel threads
        slist_data_t *datap;
        while(!SLIST_EMPTY(&head)) {
            datap = SLIST_FIRST(&head);
            if (datap->complete) {
                if (pthread_join(datap->ptid, NULL) != 0) {
                    printf("failed to join thread with id: %lx\n", datap->ptid);
                }
            } else {
                if (pthread_cancel(datap->ptid) != 0) {
                    perror("pthread_cancel");
                    printf("Failed to cancel thread with id:\t%lx\n", datap->ptid);
                }
            }
            SLIST_REMOVE_HEAD(&head, entries);
        }

        syslog(LOG_INFO, "Caught signal, exiting");
        cleanup();
        exit(0);
    }
}

int write_to_file(int writefd, const void* buf, size_t write_size) {
    int bytes_written = write(writefd, buf, write_size);
    if (bytes_written == -1) {
        perror("write");
        return -1;
    } else if (bytes_written < write_size) {
        printf("Attempted to write %ld bytes, only wrote %d\n", write_size, bytes_written);
    }
    return 0;
}

int send_temp_file(int sockfd, int tempfd) {
    #if USE_AESD_CHAR_DEVICE == 0
        int pos = lseek(tempfd, 0, SEEK_SET); // seek to beginning of file
        if (pos == -1) {
            perror("lseek");
            return -1;
        }
    #endif /* USE_AESD_CHAR_DEVICE == 0*/

    char tempbuf[1024];
    size_t bytes_read = read(tempfd, tempbuf, sizeof(tempbuf));
    while (bytes_read != 0) {
        if (bytes_read == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("read");
            return -1;
        }

        int ret = write_to_file(sockfd, tempbuf, bytes_read);
        if (ret != 0) {
            return ret;
        }
        bytes_read = read(tempfd, tempbuf, sizeof(tempbuf));
    }

    return 0;
}

// connection thread
// params - sockfd_new, logfd (global)
// shared data - logfd, pbuf (could refactor)
// thread cleanup - free pbuf.data, free socket
void *conn_func(void* params) {
    slist_data_t *llparams = (slist_data_t *)params;
    int sockfd = llparams->sockfd;
    int *complete = &llparams->complete;

    int rc;

    // allocate pbuf structure
    struct packet_buffer pbuf;
    memset(&pbuf, 0, sizeof(struct packet_buffer));
    rc = pbuf_alloc(&pbuf);

    char *sop = pbuf.data;
    while (rc == 0) {
        // read bytes from network
        int remaining = pbuf.size - pbuf.ptr;
        int bytes_recv = recv(sockfd, pbuf.data + pbuf.ptr, remaining - 1, 0);
        if (bytes_recv == -1) {
            perror("recv");
            break;
        } else if (bytes_recv == 0) {
            syslog(LOG_DEBUG, "connection terminated\n");
            break;
        } else {
            // separate into packets demarcated by '\n'
            char *last = pbuf.data + pbuf.ptr + bytes_recv;
            *last = '\0'; // make it a null-terminated string
            char *eop = strchr(sop, '\n');
            while (eop != NULL) {
                #if USE_AESD_CHAR_DEVICE == 1
                    devfd = open(dev_driver, O_RDWR);
                    if (devfd == -1) {
                        perror("open device");
                        break;
                    }
                    rc = write_to_file(devfd, sop, eop + 1 - sop);
                    if (rc != 0) {
                        break;
                    }

                    rc = send_temp_file(sockfd, devfd);
                    if (rc != 0) {
                        break;
                    }

                #else
                    rc = pthread_mutex_lock(&logfd_mutex);
                    if (rc != 0) {
                        printf("pthread_mutex_lock failed with %d\n", rc);
                        break;
                    }

                    rc = write_to_file(logfd, sop, eop + 1 - sop);
                    if (rc != 0) {
                        break;
                    }

                    rc = send_temp_file(sockfd, logfd);
                    if (rc != 0) {
                        break;
                    }

                    rc = pthread_mutex_unlock(&logfd_mutex);
                    if (rc != 0) {
                        break;
                    }
                #endif /* USE_AESD_CHAR_DEVICE */

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
                rc = pbuf_alloc(&pbuf);
                if (rc != 0) {
                    break;
                }
                // realloc could change the base pointer, need to adjust sop in that case
                if (pbuf.data != pbuf_data_old) {
                    sop = pbuf.data + (sop - pbuf_data_old);
                }
            }
        }
    }

    // cleanup. The program flow should always reach this point
    free(pbuf.data);
    close(sockfd);
    if (devfd) {
        close(devfd);
    }

    *complete = 1;

    return NULL;
}

void timelogger_func(int signo) {
    // get RFC 2822 date format
    // "%a, %d %b %Y %T %z"
    char timestr[200];
    char *timefmt = "timestamp:%a, %d %b %Y %T %z\n";
    struct timespec ts;
    struct tm tm;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        perror("clock_gettime");
        return;
    }
    localtime_r(&ts.tv_sec, &tm);
    if (strftime(timestr, sizeof(timestr), timefmt, &tm) == 0) {
        perror("strftime");
        return;
    }
    if (pthread_mutex_lock(&logfd_mutex)) {
        perror("pthread_mutex_lock");
        return;
    }
    write_to_file(logfd, timestr, strlen(timestr));
    if (pthread_mutex_unlock(&logfd_mutex)) {
        perror("pthread_mutex_unlock");
        return;
    }

    return;
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

    // get sockaddr
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

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
        int ret = dup(0);
        if (ret == -1) printf("dup failed\n");
        ret = dup(0);
        if (ret == -1) printf("dup failed\n");
    }

    #if USE_AESD_CHAR_DEVICE == 0
        // open file for appending
        int wrflags = O_RDWR | O_APPEND | O_CREAT;
        logfd = open(temp_filename, wrflags, S_IROTH);
        if (logfd == -1) {
            perror("open");
            cleanup();
            exit(1);
        }

        // initialize mutex
        if (pthread_mutex_init(&logfd_mutex, NULL) != 0) {
            printf("mutex initialization failed\n");
            cleanup();
            exit(1);
        }

        // set up a timer to log the time
        struct itimerval delay;

        signal (SIGALRM, timelogger_func);

        delay.it_value.tv_sec = 10;
        delay.it_value.tv_usec = 0;
        delay.it_interval.tv_sec = 10;
        delay.it_interval.tv_usec = 0;
        status = setitimer(ITIMER_REAL, &delay, NULL);
        if (status) {
            perror("setitimer");
            cleanup();
            exit(1);
        }
    #endif /* USE_AESD_CHAR_DEVICE */

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
        int sockfd_new = accept(sockfd, &addr_conn, &addr_conn_len);
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

        slist_data_t *datap = malloc(sizeof(slist_data_t));
        datap->sockfd = sockfd_new;
        datap->complete = 0;

        SLIST_INSERT_HEAD(&head, datap, entries);

        // spawn thread with conn_func
        int rc = pthread_create(&datap->ptid, NULL, &conn_func, (void*)datap);
        if (rc != 0) {
            perror("pthread_create");
            cleanup();
            exit(1);
        }

        // check other threads for completion
        int done = 0;
        while(!done) {
            done = 1;
            SLIST_FOREACH(datap, &head, entries) {
                if (datap->complete == 1) {
                    // join thread, remove from LL, and free memory
                    pthread_join(datap->ptid, NULL);
                    SLIST_REMOVE(&head, datap, slist_data_s, entries);
                    free(datap);
                    // after we remove an element, start over from the beginning
                    // not super efficient, but at least it's safe
                    done = 0;
                    break;
                }
            }
        }

    }

    cleanup();

    return 0;
}
