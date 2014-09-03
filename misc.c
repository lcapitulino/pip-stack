#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/if.h>
#include <linux/if_tun.h>

#include "misc.h"
#include "common.h"

int tun_open(const char *dev)
{
	struct ifreq ifr;
	int fd, err;

	if (!dev)
		return -EINVAL;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0)
		return -1;

	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	err = ioctl(fd, TUNSETIFF, &ifr);
	if (err < 0) {
		close(fd);
		return err;
	}

	return fd;
}

void tun_close(int fd)
{
	close(fd);
}
