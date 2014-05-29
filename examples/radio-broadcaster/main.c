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

#include <string.h>
#include <stdint.h>

#include <blessed/timer.h>
#include <blessed/log.h>

#include "radio.h"

/* Link Layer specification Section 2.1.2, Core 4.1 page 2503 */
#define ADV_CHANNEL_AA			0x8E89BED6

/* Link Layer specification Section 3.1.1, Core 4.1 page 2522 */
#define ADV_CHANNEL_CRC			0x555555

#define ADV_EVENT			100
#define ADV_INTERVAL			5

/* Link Layer specification section 2.3, Core 4.1, page 2504
 * Link Layer specification section 2.3.1.3, Core 4.1, page 2507
 *
 * ADV_NONCONN_IND PDU (39 octets):
 * +--------+--------+---------+
 * | Header |  AdvA  | AdvData |
 * +--------+--------+---------+
 *  2 octets 6 octets 31 octets
 *
 * Header: PDU Type=ADV_NONCONN_IND, TxAddr=1, Length=32
 * AdvA: FF:EE:DD:CC:BB:AA
 * AdvData: AD structure:
 * LEN: 15 bytes | LOCAL NAME: 0x09 | DATA: "blessed device"
 */
static const uint8_t pdu[] = {	0x42, 0x16,	/* Header */
				0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,

				0x0F,	/* EIR Struct 1 length */
				      0x09,	/* Type: Complete local name */
				      0x62, 0x6C, 0x65, 0x73,  0x73, 0x65, 0x64, 0x20,
				      0x64, 0x65, 0x76, 0x69,  0x63, 0x65
};

static uint8_t channels[] = { 37, 38, 39 };
static uint8_t idx;

static int16_t adv_event;
static int16_t adv_interval;

void adv_interval_timeout(void *user_data)
{
	radio_send(channels[idx++], ADV_CHANNEL_AA, ADV_CHANNEL_CRC, pdu,
								sizeof(pdu));

	if (idx < 3)
		timer_start(adv_interval, ADV_INTERVAL, NULL);
}

void adv_event_timeout(void *user_data)
{
	idx = 0;
	adv_interval_timeout(NULL);
}

int main(void)
{
	log_init();
	timer_init();
	radio_init(NULL);

	adv_interval = timer_create(TIMER_SINGLESHOT, adv_interval_timeout);
	adv_event = timer_create(TIMER_REPEATED, adv_event_timeout);

	DBG("Advertising with:");
	DBG("Time between PDUs: %u ms", ADV_INTERVAL);
	DBG("T_advEvent:        %u ms", ADV_EVENT);

	timer_start(adv_interval, ADV_INTERVAL, NULL);
	timer_start(adv_event, ADV_EVENT, NULL);

	adv_event_timeout(NULL);

	while (1);

	return 0;
}
