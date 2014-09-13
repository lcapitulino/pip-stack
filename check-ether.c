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

START_TEST(test_dev_alloc_no_hwaddr)
{
	struct ether_device *dev;
	uint8_t hwaddr[6];

	dev = ether_dev_alloc(NULL);
	ck_assert(dev != NULL);

	ck_assert_int_eq(dev->fd, -1);
	ck_assert_int_eq(dev->cnt, 1);
	memset(hwaddr, 0, sizeof(hwaddr));
	ck_assert_int_eq(hwaddr_eq(dev->hwaddr, hwaddr), true);

	ether_dev_put(dev);
}
END_TEST

Suite *ether_suite(void)
{
	Suite *s;
	TCase *tc_frame;

	s = suite_create("Ethernet");

	tc_frame = tcase_create("Frame");

	tcase_add_test(tc_frame, test_dev_alloc_no_hwaddr);
	suite_add_tcase(s, tc_frame);

	return s;
}

int main(void)
{
	int nr_failed;
	SRunner *sr;
	Suite *s;

	s = ether_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	nr_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (nr_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
