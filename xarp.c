#include "common.h"
#include "misc.h"

int main(int argc, char *argv[])
{
	uint8_t buf[12];
	ssize_t ret;
	int fd;

	if (argc != 2) {
		fprintf(stderr, "xarg <tap device>\n");
		exit(1);
	}

	fd = tun_open(argv[1]);
	if (fd < 0) {
		perror("tun_open()");
		exit(1);
	}

	while (true) {
		char hwaddr_str[64];
		ret = read(fd, buf, 12);
		if (ret < 0) {
			perror("read()");
			break;
		}

		hwaddr_to_str(buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
					  hwaddr_str, sizeof(hwaddr_str));
		fprintf(stderr, "-> dst: %s\n", hwaddr_str);

		hwaddr_to_str(buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
					  hwaddr_str, sizeof(hwaddr_str));
		fprintf(stderr, "-> src: %s\n\n", hwaddr_str);

	}

	close(fd);
	return 0;
}
