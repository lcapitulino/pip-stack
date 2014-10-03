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
#include <sys/time.h>

#include "common.h"
#include "utils.h"
#include "ether.h"
#include "arp.h"
#include "ipv4.h"

#define ICMP_PKT_SIZE 64

struct uping_stack {
	struct ether_device *dev;
	struct ipv4_module *ipv4_mod;
};

struct uping_info {
	size_t datagram_size;
	int ttl;
	suseconds_t time;
	uint16_t id;
	uint16_t seq;
};

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
										uint16_t id, uint16_t seq)
{
	uint8_t icmp_req[ICMP_PKT_SIZE];
	int ret;

	uping_build_icmp_echo_request(icmp_req, sizeof(icmp_req), id, seq);

	ret = ipv4_send(dev, ipv4_mod, ipv4_dst_addr, IPV4_PROT_ICMP,
                    icmp_req, sizeof(icmp_req));

	return ret;
}

static int uping_handle_icmp(struct ether_frame *frame, void *data)
{
	struct uping_info *info = data;
	struct ipv4_datagram *ipv4_dtg;
	int ret = ETHER_DISP_CONT;
	uint16_t *idp, *seqp;
	const uint8_t *p;

	ipv4_dtg = ipv4_datagram_from_data(ether_get_data(frame),
                                       ether_get_data_size(frame));
	if (!ipv4_dtg)
		return ETHER_DISP_ERR;

	if (!ipv4_datagram_is_good(ipv4_dtg))
		goto out;

	if (ipv4_get_protocol(ipv4_dtg) != IPV4_PROT_ICMP)
		goto out;

	p = ipv4_get_data(ipv4_dtg);
	assert(p != NULL);

	idp = (uint16_t *) &p[4];
	seqp = (uint16_t *) &p[6];
	if (ntohs(*idp) == info->id && ntohs(*seqp) == info->seq) {
		info->ttl = ipv4_get_ttl(ipv4_dtg);
		info->datagram_size = ipv4_get_data_size(ipv4_dtg);
		memcpy(&info->time, &p[8], sizeof(info->time));
		ret = ETHER_DISP_QUIT;
	}

out:
	ipv4_datagram_free(ipv4_dtg);
	return ret;
}

static int uping_recv_icmp_echo_reply(struct ether_device *dev,
                                      struct uping_info *info)
{
	struct ether_dispatch dispatch;
	int err;

	memset(&dispatch, 0, sizeof(dispatch));
	dispatch.handler_ipv4 = uping_handle_icmp;
	dispatch.data = info;

	err = ether_dev_recv_dispatch(dev, &dispatch, 2);
	errno = dispatch.err_num;
	return err;
}

static void uping_loop(struct uping_stack *uping_stack,
                       const char *ipv4_addr_ping_str, uint32_t ipv4_addr_ping)
{
	struct uping_info info;
	int ret, id, seq;

	id = getpid();

	for (seq = 1; ; seq++) {
		ret = uping_send_icmp_echo_request(uping_stack->dev,
    	                                   uping_stack->ipv4_mod,
										   ipv4_addr_ping, id, seq);
		if (ret < 0) {
			perror("uping_send_icmp_echo_request()");
			exit(1);
		}

		info.id = id;
		info.seq = seq;
		ret = uping_recv_icmp_echo_reply(uping_stack->dev, &info);
		if (!ret) {
			fprintf(stderr,
				"%d bytes from %s: icmp_seq=%d ttl=%d time=%1.3f ms\n",
				(int) info.datagram_size, ipv4_addr_ping_str, seq,
				info.ttl, (float) time_diff_now(info.time) * 0.001);
		} else if (ret == -2) {
			fprintf(stderr, "no response received (timeout)\n");
		} else {
			perror("failed getting icmp response");
		}

		if (seq == USHRT_MAX)
			seq = 1;

		sleep(1);
	}
}

static void uping_stack_init(struct uping_stack *uping_stack,
                             const char *config_file_path)
{
	int ret;

	uping_stack->ipv4_mod = ipv4_module_init(config_file_path);
	if (!uping_stack->ipv4_mod) {
		perror("ipv4_module_alloc()");
		exit(1);
	}

	uping_stack->dev = ether_dev_alloc(uping_stack->ipv4_mod->hwaddr);
	if (!uping_stack->dev) {
		perror("ether_dev_alloc()");
		exit(1);
	}

	ret = ether_dev_open(uping_stack->dev, uping_stack->ipv4_mod->ifname);
	if (ret < 0) {
		perror("ether_dev_open()");
		exit(1);
	}
}

static void usage(void)
{
	printf("uping <config-file> <ipv4-addr>\n");
}

int main(int argc, char *argv[])
{
	const char *ipv4_addr_ping_str;
	struct uping_stack uping_stack;
	uint32_t ipv4_addr_ping;

	if (argc != 3) {
		usage();
		exit(1);
	}

	uping_stack_init(&uping_stack, argv[1]);

	ipv4_addr_ping_str = argv[2];
	ipv4_addr_ping = inet_network(ipv4_addr_ping_str);

	fprintf(stderr, "PING %s (%s) %d bytes of data\n", ipv4_addr_ping_str,
            ipv4_addr_ping_str, ICMP_PKT_SIZE);

	/*
	 * XXX: Without this sending a packet through the tap interface
	 * fails. It seems that the tap interface needs some time to
	 * detect an application has opened it.
	 */
	sleep(1);

	uping_loop(&uping_stack, ipv4_addr_ping_str, ipv4_addr_ping);

	return 0;
}
