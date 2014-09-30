/*
 *  Copyright 2014 Luiz Capitulino
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation version 2.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <libconfig.h>
#include <sys/time.h>

#include "common.h"
#include "utils.h"
#include "ether.h"
#include "arp.h"
#include "ipv4.h"

struct uping_config {
	char *ipv4_addr_ping_str;
	bool verbose;

	/* ipv4 stack config */
	char *iface;
	char *ipv4_addr_host_str;
	char *hwaddr_host_str;
};

struct uping_stack {
	struct ether_device *dev;
	struct ipv4_module *ipv4_mod;
};

struct uping_info {
	size_t datagram_size;
	int ttl;
	suseconds_t time;
};

static bool verbose_on(const struct uping_config *uping_cfg)
{
	return uping_cfg->verbose;
}

static void xconfig_lookup_string(config_t *cfg,
                                  const char *key, const char **str,
								  const char *config_file_path)
{
	int ret;

	ret = config_lookup_string(cfg, key, str);
	if (!ret) {
		fprintf(stderr, "ERROR: could not locate '%s' in '%s'\n",
                        "iface", config_file_path);
		exit(1);
	}
}

static void read_ipv4_config(const char *config_file_path,
                             struct uping_config *uping_cfg)
{
	const char *str;
	config_t cfg;
	int ret;

	config_init(&cfg);

	ret = config_read_file(&cfg, config_file_path);
	if (!ret) {
		fprintf(stderr, "%s:%d - %s\n",
                        config_error_file(&cfg),
						config_error_line(&cfg),
						config_error_text(&cfg));
		exit(1);
	}

	xconfig_lookup_string(&cfg, "iface", &str, config_file_path);
	uping_cfg->iface = xstrdup(str);

	xconfig_lookup_string(&cfg, "ipv4_addr", &str, config_file_path);
	uping_cfg->ipv4_addr_host_str = xstrdup(str);

	xconfig_lookup_string(&cfg, "hwaddr", &str, config_file_path);
	uping_cfg->hwaddr_host_str = xstrdup(str);

	config_destroy(&cfg);
}

static void usage(void)
{
	printf("uping <-c file> [-v] ipv4-address\n");
}

static void uping_config_init(int argc, char *argv[],
                              struct uping_config *uping_cfg)
{
	const char *config_file = NULL;
	int opt;

	memset(uping_cfg, 0, sizeof(*uping_cfg));

	/* parse command line options */
	while ((opt = getopt(argc, argv, "c:v")) != -1) {
		switch (opt) {
		case 'c':
			config_file = optarg;
			break;
		case 'v':
			uping_cfg->verbose = true;
			break;
		case 'h':
		default:
			usage();
			exit(1);
		}
	}

	die_if_not_passed("-c", config_file);

	if ((optind + 1) != argc) {
		usage();
		exit(1);
	}

	uping_cfg->ipv4_addr_ping_str = argv[optind];

	/* read config file */
	read_ipv4_config(config_file, uping_cfg);
}

static void uping_stack_init(const struct uping_config *uping_cfg,
                             struct uping_stack *uping_stack)
{
	uint8_t hwaddr[6];
	int ret;

	ret = ether_str_to_addr(uping_cfg->hwaddr_host_str, hwaddr);
	if (ret < 0) {
		fprintf(stderr, "ERROR: bad hardware address: %s\n",
		                uping_cfg->hwaddr_host_str);
		exit(1);
	}

	uping_stack->dev = ether_dev_alloc(hwaddr);
	if (!uping_stack->dev) {
		perror("ether_dev_alloc()");
		exit(1);
	}

	ret = ether_dev_open(uping_stack->dev, uping_cfg->iface);
	if (ret < 0) {
		perror("ether_dev_open()");
		exit(1);
	}

	uping_stack->ipv4_mod = ipv4_module_alloc(uping_cfg->ipv4_addr_host_str);
	if (!uping_stack->ipv4_mod) {
		perror("ipv4_module_alloc()");
		exit(1);
	}
}

static void uping_config_destroy(struct uping_config *uping_cfg)
{
	free(uping_cfg->iface);
	free(uping_cfg->ipv4_addr_host_str);
	free(uping_cfg->hwaddr_host_str);
}

/*
 * TODO: move this to the arp module, but we also need a function
 * in the ether module capable of dispatching packets to callbacks.
 */
static int arp_find_hwaddr(struct ether_device *dev, uint32_t ipv4_src_addr,
                           uint32_t ipv4_dst_addr, uint8_t *hwaddr)
{
	struct arp_packet *arp_pkt;
	struct ether_frame *frame;
	int err;

	hwaddr_init(hwaddr, 0);

	arp_pkt = arp_build_request(dev->hwaddr, ipv4_src_addr, ETHER_TYPE_IPV4,
                                ipv4_dst_addr);
	if (!arp_pkt)
		return -1;

	err = ether_dev_send_bcast(dev, ETHER_TYPE_ARP, arp_pkt->buf,
                               ARP_PACKET_SIZE);
	if (err < 0) {
		err = errno;
		arp_packet_free(arp_pkt);
		errno = err;
		return -1;
	}

	while (true) {
		arp_packet_free(arp_pkt);

		/* TODO: ether_dev_recv() should have a timeout option */
		frame = ether_dev_recv(dev);
		if (!frame)
			return -1;

		if (ether_get_type(frame) != ETHER_TYPE_ARP) {
			ether_frame_free(frame);
			arp_pkt = NULL;
			continue;
		}

		arp_pkt = arp_packet_from_data(ether_get_data(frame),
		                               ether_get_data_size(frame));
		if (!arp_pkt) {
			err = errno;
			ether_frame_free(frame);
			errno = err;
			return -1;
		}

		ether_frame_free(frame);

		if (!arp_packet_is_good(arp_pkt))
			continue;

		if (arp_get_oper(arp_pkt) != ARP_OP_REP)
			continue;

		if (arp_get_spa(arp_pkt) != ipv4_dst_addr)
			continue;

		hwaddr_cp(hwaddr, arp_get_sha(arp_pkt));
		arp_packet_free(arp_pkt);

		return 0;
	}

	/* impossible */
	return -1;
}

static suseconds_t get_time(void)
{
	struct timeval tv;
	int err;

	memset(&tv, 0, sizeof(tv));
	err = gettimeofday(&tv, NULL);
	assert(err == 0);

	return tv.tv_usec;
}

static suseconds_t time_diff_now(suseconds_t before)
{
	return get_time() - before;
}

static void uping_build_icmp_echo_request(uint8_t *buf, size_t len,
                                          uint16_t id, uint16_t seq)
{
	suseconds_t t;
	uint16_t *p;

	assert(len >= 8);

	memset(buf, 0, len);

	/* type */
	buf[0] = 8;

	/* identification */
	p = (uint16_t *) &buf[4];
	*p = htons(id);

	/* sequence number */
	p = (uint16_t *) &buf[6];
	*p = htons(seq);

	/* data */
	t = get_time();
	memcpy(&buf[8], &t, sizeof(t));

	/* checksum */
	p = (uint16_t *) &buf[2];
	*p = calculate_net_checksum(buf, 8 + sizeof(t));

}

static int uping_send_icmp_echo_request(struct ether_device *dev,
                                        struct ipv4_module *ipv4_mod,
										uint32_t ipv4_dst_addr,
										uint8_t *dst_hwaddr, uint16_t id)
{
	struct ipv4_datagram *ipv4_dtg;
	uint8_t icmp_req[64];
	int ret;

	uping_build_icmp_echo_request(icmp_req, sizeof(icmp_req), getpid(), id);

	ipv4_dtg = ipv4_build_datagram(ipv4_mod->ipv4_addr, ipv4_dst_addr, 1,
                                   icmp_req, sizeof(icmp_req));
	if (!ipv4_dtg)
		return -1;

	ret = ether_dev_send(dev, dst_hwaddr, ETHER_TYPE_IPV4,
                         ipv4_dtg->buf, ipv4_dtg->data_size + IPV4_HEADER_SIZE);

	ipv4_datagram_free(ipv4_dtg);
	return ret;
}

static int uping_recv_icmp_echo_reply(struct ether_device *dev,
                                      uint16_t id, uint16_t seq,
                                      struct uping_info *info)
{
	struct ipv4_datagram *ipv4_dtg;
	struct ether_frame *frame;
	uint16_t *idp, *seqp;
	uint8_t *data;

	memset(info, 0, sizeof(*info));

	while (true) {
		/* TODO: ether_dev_recv() should have a timeout option */
		frame = ether_dev_recv(dev);
		if (!frame)
			return -1;

		if (ether_get_type(frame) != ETHER_TYPE_IPV4) {
			ether_frame_free(frame);
			continue;
		}

		if (!hwaddr_eq(ether_get_dst(frame), dev->hwaddr)) {
			ether_frame_free(frame);
			continue;
		}

		ipv4_dtg = ipv4_datagram_from_data(ether_get_data(frame),
                                           ether_get_data_size(frame));
		if (!ipv4_dtg) {
			ether_frame_free(frame);
			continue;
		}

		ether_frame_free(frame);

		if (ipv4_get_protocol(ipv4_dtg) != 1) {
			ipv4_datagram_free(ipv4_dtg);
			continue;
		}

		/* Check all other fields (version, ihl, checksum, etc) */
		data = ipv4_get_data(ipv4_dtg);
		assert(data != NULL);

		idp = (uint16_t *) &data[4];
		seqp = (uint16_t *) &data[6];
		if (ntohs(*idp) == id && ntohs(*seqp) == seq) {
			info->ttl = ipv4_get_ttl(ipv4_dtg);
			info->datagram_size = ipv4_get_data_size(ipv4_dtg);
			memcpy(&info->time, &data[8], sizeof(info->time));
			ipv4_datagram_free(ipv4_dtg);
			return 0;
		}
	}

	/* impossible */
	return -1;
}

int main(int argc, char *argv[])
{
	struct uping_config uping_cfg;
	struct uping_stack uping_stack;
	uint32_t ipv4_addr_ping;
	struct uping_info info;
	uint8_t hwaddr[6];
	char str[32];
	int seq, ret;

	uping_config_init(argc, argv, &uping_cfg);

	if (verbose_on(&uping_cfg)) {
		fprintf(stderr, "iface: %s\n", uping_cfg.iface);
		fprintf(stderr, "host ipv4 address: %s\n",uping_cfg.ipv4_addr_host_str);
		fprintf(stderr, "host hwaddr: %s\n", uping_cfg.hwaddr_host_str);
		fprintf(stderr, "address to ping: %s\n", uping_cfg.ipv4_addr_ping_str);
		fprintf(stderr, "\n\n");
	}

	uping_stack_init(&uping_cfg, &uping_stack);
	ipv4_addr_ping = inet_network(uping_cfg.ipv4_addr_ping_str);

	sleep(1);

	/* TODO: add assessors for these objects */
	ret = arp_find_hwaddr(uping_stack.dev, uping_stack.ipv4_mod->ipv4_addr,
                          ipv4_addr_ping, hwaddr);
	if (ret < 0) {
		perror("arp_find_hwaddr()");
		exit(1);
	}

	if (verbose_on(&uping_cfg)) {
		memset(str, 0, sizeof(str));
		ether_addr_to_str(hwaddr, str, sizeof(str));
		printf("%s is %s\n", uping_cfg.ipv4_addr_ping_str, str);
	}

	fprintf(stderr, "PING %s (%s)\n", uping_cfg.ipv4_addr_ping_str,
            uping_cfg.ipv4_addr_ping_str);

	for (seq = 1; ; seq++) {
		ret = uping_send_icmp_echo_request(uping_stack.dev,
    	                                   uping_stack.ipv4_mod,
										   ipv4_addr_ping, hwaddr, seq);
		if (ret < 0) {
			perror("uping_send_icmp_echo_request()");
			exit(1);
		}

		ret = uping_recv_icmp_echo_reply(uping_stack.dev,
    	                                 getpid(), seq, &info);
		if (!ret) {
			fprintf(stderr,
				"%d bytes from %s: icmp_seq=%d ttl=%d time=%1.3f ms\n",
				(int) info.datagram_size, uping_cfg.ipv4_addr_ping_str,
				seq, info.ttl, (float) time_diff_now(info.time) * 0.001);
		} else {
			fprintf(stderr, "failed getting icmp response\n");
		}

		if (seq == SHRT_MAX)
			seq = 1;

		sleep(1);
	}

	uping_config_destroy(&uping_cfg);

	return 0;
}
