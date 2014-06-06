/**
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2013 Paulo B. de Oliveira Filho <pauloborgesfilho@gmail.com>
 *  Copyright (c) 2013 Claudio Takahasi <claudio.takahasi@gmail.com>
 *  Copyright (c) 2013 João Paulo Rechi Vita <jprvita@gmail.com>
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <blessed/errcodes.h>
#include <blessed/log.h>
#include <blessed/timer.h>
#include <blessed/bdaddr.h>

#include "radio.h"
#include "ll.h"

/* Link Layer specification Section 2.1.2, Core 4.1 page 2503 */
#define LL_ACCESS_ADDRESS_ADV		0x8E89BED6

/* Link Layer specification Section 3.1.1, Core 4.1 page 2522 */
#define LL_CRCINIT_ADV			0x555555

/* Link Layer specification Section 1.1, Core 4.1 page 2499 */
typedef enum ll_states {
	LL_STATE_STANDBY,
	LL_STATE_ADVERTISING,
	LL_STATE_SCANNING,
	LL_INITIATING_SCANNING,
	LL_CONNECTION_SCANNING,
} ll_states_t;

/* Link Layer specification Section 2.3, Core 4.1 pages 2504-2505 */
struct __attribute__ ((packed)) ll_pdu_adv {
	uint8_t		pdu_type:4;	/* See ll_pdu_t */
	uint8_t		_rfu_0:2;	/* Reserved for future use */
	uint8_t		tx_add:1;	/* public (0) or random (1) */
	uint8_t		rx_add:1;	/* public (0) or random (1) */

	uint8_t		length:6;	/* 6 <= payload length <= 37 */
	uint8_t		_rfu_1:2;	/* Reserved for future use */

	uint8_t		payload[LL_ADV_MTU_PAYLOAD];
};

static const bdaddr_t *laddr;
static ll_states_t current_state;

#define ADV_CH_IDX_37		0
#define ADV_CH_IDX_38		1
#define ADV_CH_IDX_39		2

static uint8_t adv_chs[] = { 37, 38, 39 };
static uint8_t adv_ch_idx;
static uint8_t adv_ch_map;

static int16_t t_adv_event;
static uint32_t t_adv_event_interval;
static int16_t t_adv_pdu;
static uint32_t t_adv_pdu_interval;

static struct ll_pdu_adv pdu_adv;
static struct ll_pdu_adv pdu_scan_rsp;

static __inline uint8_t first_adv_ch_idx(void)
{
	if (adv_ch_map & LL_ADV_CH_37)
		return ADV_CH_IDX_37;
	else if (adv_ch_map & LL_ADV_CH_38)
		return ADV_CH_IDX_38;
	else
		return ADV_CH_IDX_39;
}

static __inline int16_t inc_adv_ch_idx(void)
{
	if ((adv_ch_map & LL_ADV_CH_38) &&
					(adv_ch_idx == ADV_CH_IDX_37))
		adv_ch_idx = ADV_CH_IDX_38;
	else if ((adv_ch_map & LL_ADV_CH_39) &&
					(adv_ch_idx < ADV_CH_IDX_39))
		adv_ch_idx = ADV_CH_IDX_39;
	else
		return -1;

	return 0;
}

static void t_adv_pdu_cb(void *user_data)
{
	radio_send(adv_chs[adv_ch_idx], LL_ACCESS_ADDRESS_ADV, LL_CRCINIT_ADV,
					(uint8_t *) &pdu_adv, sizeof(pdu_adv));

	if (!inc_adv_ch_idx())
		timer_start(t_adv_pdu, t_adv_pdu_interval, NULL);
}

static void t_adv_event_cb(void *user_data)
{
	adv_ch_idx = first_adv_ch_idx();
	t_adv_pdu_cb(NULL);
}

int16_t ll_advertise_start(ll_pdu_t type, uint16_t interval, uint8_t chmap)
{
	int16_t err_code;

	if (current_state != LL_STATE_STANDBY)
		return -ENOREADY;

	if (!chmap || (chmap & !LL_ADV_CH_ALL))
		return -EINVAL;

	adv_ch_map = chmap;

	switch (type) {
	case LL_PDU_ADV_IND:
	case LL_PDU_ADV_DIRECT_IND:
	case LL_PDU_ADV_SCAN_IND:
		/* Not implemented */
		return -EINVAL;
	case LL_PDU_ADV_NONCONN_IND:
		if (interval < LL_ADV_INTERVAL_MIN_NONCONN
					|| interval > LL_ADV_INTERVAL_MAX)
			return -EINVAL;

		pdu_adv.pdu_type = LL_PDU_ADV_NONCONN_IND;

		t_adv_event_interval = interval;
		t_adv_pdu_interval = 5; /* <= 10ms Sec 4.4.2.6 pag 2534*/

		break;
	default:
		/* Invalid PDU */
		return -EINVAL;
	}

	err_code = timer_start(t_adv_event, t_adv_event_interval, NULL);
	if (err_code < 0)
		return err_code;

	t_adv_event_cb(NULL);
	current_state = LL_STATE_ADVERTISING;

	DBG("PDU interval %ums, event interval %ums", t_adv_pdu_interval,
							t_adv_event_interval);

	return 0;
}

int16_t ll_advertise_stop()
{
	int16_t err_code;

	if (current_state != LL_STATE_ADVERTISING)
		return -ENOREADY;

	err_code = timer_stop(t_adv_pdu);
	if (err_code < 0)
		return err_code;

	err_code = timer_stop(t_adv_event);
	if (err_code < 0)
		return err_code;

	current_state = LL_STATE_STANDBY;

	return 0;
}

int16_t ll_set_advertising_data(const uint8_t *data, uint8_t len)
{
	if (current_state != LL_STATE_STANDBY)
		return -EBUSY;

	if (data == NULL)
		return -EINVAL;

	if (len > LL_ADV_MTU_DATA)
		return -EINVAL;

	memcpy(pdu_adv.payload + sizeof(laddr->addr), data, len);
	pdu_adv.length = sizeof(laddr->addr) + len;

	return 0;
}

int16_t ll_set_scan_response_data(const uint8_t *data, uint8_t len)
{
	if (data == NULL)
		return -EINVAL;

	if (len > LL_ADV_MTU_DATA)
		return -EINVAL;

	memcpy(pdu_scan_rsp.payload + sizeof(laddr->addr), data, len);
	pdu_scan_rsp.length = sizeof(laddr->addr) + len;

	return 0;
}

static void init_adv_pdus(void)
{
	pdu_adv.tx_add = laddr->type;
	memcpy(pdu_adv.payload, laddr->addr, sizeof(laddr->addr));

	ll_set_advertising_data(NULL, 0);

	pdu_scan_rsp.tx_add = laddr->type;
	memcpy(pdu_scan_rsp.payload, laddr->addr, sizeof(laddr->addr));

	ll_set_scan_response_data(NULL, 0);
}

int16_t ll_init(const bdaddr_t *addr)
{
	int16_t err_code;

	if (addr == NULL)
		return -EINVAL;

	err_code = log_init();
	if (err_code < 0 && err_code != -EALREADY)
		return err_code;

	err_code = timer_init();
	if (err_code < 0)
		return err_code;

	err_code = radio_init(NULL);
	if (err_code < 0)
		return err_code;

	t_adv_event = timer_create(TIMER_REPEATED, t_adv_event_cb);
	if (t_adv_event < 0)
		return t_adv_event;

	t_adv_pdu = timer_create(TIMER_SINGLESHOT, t_adv_pdu_cb);
	if (t_adv_pdu < 0)
		return t_adv_pdu;

	laddr = addr;
	current_state = LL_STATE_STANDBY;

	init_adv_pdus();

	return 0;
}
