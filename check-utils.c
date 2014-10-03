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
#include "utils.h"

START_TEST(test_checksum_ok)
{
	uint16_t data[] = { 0x4500, 0x0073, 0x0, 0x4000, 0x4011,
						0xc0a8, 0x0001, 0xc0a8, 0x00c7, 0x0 };
	uint16_t csum;

	csum = calculate_net_checksum((uint8_t *) data, 20);
	ck_assert_int_eq(csum, 0xb861);
}
END_TEST

START_TEST(test_count_bits)
{
	int ret;

	ret = count_set_bits(0);
	ck_assert_int_eq(ret, 0);

	ret = count_set_bits(1);
	ck_assert_int_eq(ret, 1);

	ret = count_set_bits(0x270088);
	ck_assert_int_eq(ret, 6);

	ret = count_set_bits(UINT32_MAX);
	ck_assert_int_eq(ret, 32);
}
END_TEST

Suite *utils_suite(void)
{
	Suite *s;
	TCase *tc_utils;

	s = suite_create("utils");

	tc_utils = tcase_create("Core");
	tcase_add_test(tc_utils, test_checksum_ok);
	tcase_add_test(tc_utils, test_count_bits);
	suite_add_tcase(s, tc_utils);

	return s;
}

int main(void)
{
	int nr_failed;
	SRunner *sr;
	Suite *s;

	s = utils_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	nr_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (nr_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
