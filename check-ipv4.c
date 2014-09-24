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
#include "ipv4.h"

START_TEST(test_ipv4_module_alloc)
{
	const char *addr_str = "192.168.0.1";
	struct ipv4_module *ipv4_mod;

	ipv4_mod = ipv4_module_alloc(addr_str);
	ck_assert(ipv4_mod != NULL);

	ck_assert_int_eq(ipv4_mod->ipv4_addr, inet_network(addr_str));

	ipv4_module_free(ipv4_mod);
}
END_TEST

START_TEST(test_ipv4_module_alloc_free_errors)
{
	ck_assert_int_eq(ipv4_module_alloc(NULL), NULL);
	ck_assert_int_eq(ipv4_module_alloc("jandjsa"), NULL);
	ipv4_module_free(NULL);
}
END_TEST

static const uint8_t ip_datagram[] = {
             0x45,              /* version: ipv4, IHL: 5 (20 bytes header) */
			 0x00,              /* DSCP, ECN: congestion stuff, not used */
			 0x00, 0x14,        /* total length: 20 bytes (header only) */
			 0x00, 0x01,        /* Identification */      
			 0x40, 0x00,        /* Flags/Frag offset: no fragmentation */
			 0x40,              /* TTL: 64 */
			 0x11,              /* Protocol: UDP */
			 0x00, 0x00,        /* checksum: no checksum */
			 0xc0, 0xa8, 0x00, 0x2c, /* source addr: 192.168.0.44 */
			 0xc0, 0xa8, 0x00, 0x04  /* destination addr: 192.168.0.4 */
};

START_TEST(test_ipv4_datagram_from_data)
{
	struct ipv4_datagram *ipv4_dtg;
	in_addr_t addr;

	ipv4_dtg = ipv4_datagram_from_data(ip_datagram, sizeof(ip_datagram));
	ck_assert(ipv4_dtg != NULL);

	ck_assert_int_eq(ipv4_get_version(ipv4_dtg), 4);
	ck_assert_int_eq(ipv4_get_ihl(ipv4_dtg), 5);
	ck_assert_int_eq(ipv4_get_ds(ipv4_dtg), 0);
	ck_assert_int_eq(ipv4_get_ecn(ipv4_dtg), 0);
	ck_assert_int_eq(ipv4_get_length(ipv4_dtg), 20);
	ck_assert_int_eq(ipv4_get_id(ipv4_dtg), 1);
	ck_assert_int_eq(ipv4_get_flags(ipv4_dtg), IPV4_FLAGS_DF);
	ck_assert_int_eq(ipv4_get_fragoffset(ipv4_dtg), 0);
	ck_assert_int_eq(ipv4_get_ttl(ipv4_dtg), IPV4_DEF_TTL);
	ck_assert_int_eq(ipv4_get_protocol(ipv4_dtg), IPV4_PROT_UDP);
	ck_assert_int_eq(ipv4_get_checksum(ipv4_dtg), 0);

	addr = inet_network("192.168.0.44");
	ck_assert_int_eq(ipv4_get_src_addr(ipv4_dtg), addr);

	addr = inet_network("192.168.0.4");
	ck_assert_int_eq(ipv4_get_dst_addr(ipv4_dtg), addr);

	ck_assert_int_eq(ipv4_get_data_size(ipv4_dtg), 0);
	ck_assert_int_eq(ipv4_get_data(ipv4_dtg), NULL);

	ipv4_datagram_free(ipv4_dtg);
}
END_TEST

#if 0
START_TEST(test_ipv4_build_datagram)
{
}
END_TEST
#endif

Suite *ipv4_suite(void)
{
	Suite *s;
	TCase *dt_tests, *mod_tests;

	s = suite_create("IPv4");

	mod_tests = tcase_create("module");
	tcase_add_test(mod_tests, test_ipv4_module_alloc);
	tcase_add_test(mod_tests, test_ipv4_module_alloc_free_errors);
	suite_add_tcase(s, mod_tests);

	dt_tests = tcase_create("datagram");
	tcase_add_test(dt_tests, test_ipv4_datagram_from_data);
	suite_add_tcase(s, dt_tests);

	return s;
}

int main(void)
{
	int nr_failed;
	SRunner *sr;
	Suite *s;

	s = ipv4_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	nr_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (nr_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
