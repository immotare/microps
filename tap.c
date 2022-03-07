#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>

#define CLONE_DEVICE "/dev/net/tun"

int
main (int argc, char *argv[]) {
    int fd;
    struct ifreq ifr = {};
    char buf[2046];
    char *ifname;
    ssize_t n;

    if (argc != 2) {
        fprintf(stderr, "usage: %s ifname\n", argv[0]);
        return -1;
    }
    fd = open(CLONE_DEVICE, O_RDWR);
    if (fd == -1) {
        perror("open");
        return -1;
    }
    strncpy(ifr.ifr_name, argv[1], sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
        perror("ioctl [TUNSETIFF]");
        close(fd);
        return -1;
    }
    ifname = ifr.ifr_name;
    fprintf(stderr, "ifname: %s\n", ifname);
    while (1) {
        n = read(fd, buf, sizeof(buf));
        if (n == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("read");
            close(fd);
            return -1;
        }
        printf("recv: %zd via %s\n", n, ifname);
    }
    close(fd);
    return 0;
}