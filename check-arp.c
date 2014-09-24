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
#include <check.h>

#include "common.h"
#include "ether.h"
#include "arp.h"

const uint8_t hwaddr_sender[6] = { 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6 };
const uint8_t hwaddr_target[6] = { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 };

const uint8_t arp_req[ARP_PACKET_SIZE] = {
               0x00, 0x01,       /* hardware type: ethernet */
               0x08, 0x00,       /* protocol type: IPv4 */
               0x06,             /* hardware addr size: 6 (ether) */
               0x04,             /* protocol addr size: 4 (ipv4) */
               0x00, 0x02,       /* operation: ARP reply */
               0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, /* sender hwaddr */
               0xc0, 0xa8, 0x00, 0x2c, /* sender prot addr: 192.168.0.44 */
               0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, /* target hwaddr */
               0xc0, 0xa8, 0x00, 0x04  /* target prot addr: 192.168.0.4 */
};

/* We test a ARP reply here because it fills all fields */
START_TEST(test_arp_packet_from_data)
{
	struct arp_packet *arp_pkt;
	const uint8_t *p;
	in_addr_t addr;

	arp_pkt = arp_packet_from_data(arp_req, ARP_PACKET_SIZE);
	ck_assert(arp_pkt != NULL);

	ck_assert_int_eq(arp_get_htype(arp_pkt), ARP_HTYPE_ETH);
	ck_assert_int_eq(arp_get_ptype(arp_pkt), ETHER_TYPE_IPV4);
	ck_assert_int_eq(arp_get_hlen(arp_pkt), 0x6);
	ck_assert_int_eq(arp_get_plen(arp_pkt), 0x4);
	ck_assert_int_eq(arp_get_oper(arp_pkt), ARP_OP_REP);

	p = arp_get_sha(arp_pkt);
	ck_assert_int_eq(hwaddr_eq(p, hwaddr_sender), true);

	addr = inet_network("192.168.0.44");
	ck_assert_int_eq(arp_get_spa(arp_pkt), addr);

	p = arp_get_tha(arp_pkt);
	ck_assert_int_eq(hwaddr_eq(p, hwaddr_target), true);

	addr = inet_network("192.168.0.4");
	ck_assert_int_eq(arp_get_tpa(arp_pkt), addr);

	arp_packet_free(arp_pkt);
}
END_TEST

START_TEST(test_arp_build_request)
{
	struct arp_packet *arp_req;
	uint8_t hwaddr_zero[6];
	in_addr_t spa, tpa;
	const uint8_t *p;

	spa = inet_network("192.168.0.99");
	tpa = inet_network("192.168.0.1");

	arp_req = arp_build_request(hwaddr_sender, spa, ETHER_TYPE_IPV4, tpa);
	ck_assert(arp_req != 0);
	ck_assert_int_eq(arp_packet_is_good(arp_req), true);

	ck_assert_int_eq(arp_get_htype(arp_req), ARP_HTYPE_ETH);
	ck_assert_int_eq(arp_get_ptype(arp_req), ETHER_TYPE_IPV4);
	ck_assert_int_eq(arp_get_hlen(arp_req), 0x6);
	ck_assert_int_eq(arp_get_plen(arp_req), 0x4);
	ck_assert_int_eq(arp_get_oper(arp_req), ARP_OP_REQ);

	p = arp_get_sha(arp_req);
	ck_assert_int_eq(hwaddr_eq(p, hwaddr_sender), true);

	ck_assert_int_eq(arp_get_spa(arp_req), spa);

	hwaddr_init(hwaddr_zero, 0);
	p = arp_get_tha(arp_req);
	ck_assert_int_eq(hwaddr_eq(p, hwaddr_zero), true);

	ck_assert_int_eq(arp_get_tpa(arp_req), tpa);

	arp_packet_free(arp_req);
}
END_TEST

START_TEST(test_arp_build_reply)
{
	struct arp_packet *arp_req, *arp_rep;
	in_addr_t spa, tpa;
	const uint8_t *p;

	spa = inet_network("192.168.0.9");
	tpa = inet_network("192.168.0.2");

	arp_req = arp_build_request(hwaddr_sender, spa, ETHER_TYPE_IPV4, tpa);
	ck_assert(arp_req != 0);
	ck_assert_int_eq(arp_packet_is_good(arp_req), true);

	arp_rep = arp_build_reply(arp_req, hwaddr_target);
	ck_assert(arp_rep != 0);
	ck_assert_int_eq(arp_packet_is_good(arp_rep), true);

	arp_packet_free(arp_req);

	ck_assert_int_eq(arp_get_htype(arp_rep), ARP_HTYPE_ETH);
	ck_assert_int_eq(arp_get_ptype(arp_rep), ETHER_TYPE_IPV4);
	ck_assert_int_eq(arp_get_hlen(arp_rep), 0x6);
	ck_assert_int_eq(arp_get_plen(arp_rep), 0x4);
	ck_assert_int_eq(arp_get_oper(arp_rep), ARP_OP_REP);

	p = arp_get_sha(arp_rep);
	ck_assert_int_eq(hwaddr_eq(p, hwaddr_target), true);

	ck_assert_int_eq(arp_get_spa(arp_rep), tpa);

	p = arp_get_tha(arp_rep);
	ck_assert_int_eq(hwaddr_eq(p, hwaddr_sender), true);

	ck_assert_int_eq(arp_get_tpa(arp_rep), spa);

	arp_packet_free(arp_rep);
}
END_TEST

Suite *arp_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("ARP");

	tc_core = tcase_create("Core");
	tcase_add_test(tc_core, test_arp_packet_from_data);
	tcase_add_test(tc_core, test_arp_build_request);
	tcase_add_test(tc_core, test_arp_build_reply);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int nr_failed;
	SRunner *sr;
	Suite *s;

	s = arp_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	nr_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (nr_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
