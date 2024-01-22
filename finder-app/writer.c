#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

int main(int argc, char **argv) {
    // setup syslog loggin
    openlog(NULL, 0, LOG_USER);

    if (argc != 3) {
        syslog(LOG_ERR, "Usage: ./writer <write file> <write string>");
        return 1;
    }

    char *pathname = argv[1];
    char *content = argv[2];

    syslog(LOG_DEBUG, "Writing %s to %s", content, pathname);

    FILE *fd = fopen(pathname, "w");
    if (fd == NULL) {
        int err = errno;
        syslog(LOG_ERR, "Failed to open file %s: %s", pathname, strerror(err));
        return 1;
    }

    int result = fputs(content, fd);
    if (result == EOF) {
        int err = errno;
        syslog(LOG_ERR, "Write failed: %s", strerror(err));
        return 1;
    }

    fclose(fd);

    return 0;
}
