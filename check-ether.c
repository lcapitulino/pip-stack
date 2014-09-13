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

START_TEST(test_dev_alloc_hwaddr)
{
	uint8_t hwaddr[6] = { 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6 };
	struct ether_device *dev;

	dev = ether_dev_alloc(hwaddr);
	ck_assert(dev != NULL);

	ck_assert_int_eq(hwaddr_eq(dev->hwaddr, hwaddr), true);

	ether_dev_put(dev);
}
END_TEST

START_TEST(test_dev_ref_cnt)
{
	struct ether_device *dev;
	const int max = 30;
	int i;

	dev = ether_dev_alloc(NULL);
	ck_assert(dev != NULL);

	for (i = 0; i < max; i++)
		ether_dev_get(dev);

	ck_assert_int_eq(dev->cnt, max + 1);

	for (i = 0; i < max; i++)
		ether_dev_put(dev);

	ck_assert_int_eq(dev->cnt, 1);
	ether_dev_put(dev);
}
END_TEST

START_TEST(test_dev_put_null)
{
	ether_dev_put(NULL);
}
END_TEST

START_TEST(test_header_parsing_and_api)
{
	uint8_t buf[ETHER_FRAME_SIZE];
	struct ether_frame *frame;
	uint8_t hwaddr_dst[6] = { 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6 };
	uint8_t hwaddr_src[6] = { 0x1f, 0x2f, 0x3f, 0x4f, 0x5f, 0x6f };
	const uint8_t *p;
	int i = 0;

	frame = ether_frame_alloc();
	ck_assert(frame != NULL);

	/*
	 * Craft an Ethernet header
	 */

	/* destination address */
	buf[i++] = hwaddr_dst[0];
	buf[i++] = hwaddr_dst[1];
	buf[i++] = hwaddr_dst[2];
	buf[i++] = hwaddr_dst[3];
	buf[i++] = hwaddr_dst[4];
	buf[i++] = hwaddr_dst[5];

	/* source address */
	buf[i++] = hwaddr_src[0];
	buf[i++] = hwaddr_src[1];
	buf[i++] = hwaddr_src[2];
	buf[i++] = hwaddr_src[3];
	buf[i++] = hwaddr_src[4];
	buf[i++] = hwaddr_src[5];

	/* type: ETHER_TYPE_ARP */
	buf[i++] = 0x08;
	buf[i++] = 0x06;

	/* first byte in the payload */
	buf[i++] = 0xaa;

	memcpy(frame->buf, buf, ETHER_FRAME_SIZE);

	/*
	 * Now, check everything
	 */

	p = ether_get_dst(frame);
	ck_assert_int_eq(hwaddr_eq(p, hwaddr_dst), true);

	p = ether_get_src(frame);
	ck_assert_int_eq(hwaddr_eq(p, hwaddr_src), true);

	ck_assert_int_eq(ether_get_type(frame), ETHER_TYPE_ARP);

	p = ether_get_data(frame);
	ck_assert_int_eq(p[0], 0xaa);

	ether_frame_free(frame);
}
END_TEST

START_TEST(test_frame_free_null)
{
	ether_frame_free(NULL);
}
END_TEST

Suite *ether_suite(void)
{
	Suite *s;
	TCase *tc_frame;

	s = suite_create("Ethernet");

	tc_frame = tcase_create("Frame");

	tcase_add_test(tc_frame, test_dev_alloc_no_hwaddr);
	tcase_add_test(tc_frame, test_dev_alloc_hwaddr);
	tcase_add_test(tc_frame, test_dev_ref_cnt);
	tcase_add_test(tc_frame, test_dev_put_null);
	tcase_add_test(tc_frame, test_header_parsing_and_api);
	tcase_add_test(tc_frame, test_frame_free_null);
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
