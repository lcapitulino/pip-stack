#include "common.h"
#include "misc.h"

int main(int argc, char *argv[])
{
	uint8_t buf[2];
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
		ret = read(fd, buf, 1);
		if (ret < 0) {
			perror("read()");
			break;
		}

		fprintf(stderr, "0x%x\n", buf[0]);
	}

	tun_close(fd);
	return 0;
}
