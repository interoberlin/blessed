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
#include <stdbool.h>

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

/* The time between packets is 150 us. But we are only notified when a
 * transmission or reception is completed. So we need to consider the time to
 * receive the packet. Empirically, a SCAN_REQ roughly took 100 us to be totally
 * received, which gives us a total timeout of 250 us. But we will consider a
 * bigger window to guarantee the reception.
 */
#define T_IFS				500

#define LL_MAX_SIMULTANEOUS_CONNECTIONS	1

/* Link Layer specification Section 1.1, Core 4.1 page 2499 */
typedef enum ll_states {
	LL_STATE_STANDBY,
	LL_STATE_ADVERTISING,
	LL_STATE_SCANNING,
	LL_STATE_INITIATING,
	LL_STATE_CONNECTION,
} ll_states_t;

/* Link Layer specification Section 2.3, Core 4.1 pages 2504-2505 */
struct __attribute__ ((packed)) ll_pdu_adv {
	uint8_t		type:4;		/* See ll_pdu_t */
	uint8_t		_rfu_0:2;	/* Reserved for future use */
	uint8_t		tx_add:1;	/* public (0) or random (1) */
	uint8_t		rx_add:1;	/* public (0) or random (1) */

	uint8_t		length:6;	/* 6 <= payload length <= 37 */
	uint8_t		_rfu_1:2;	/* Reserved for future use */

	uint8_t		payload[LL_ADV_MTU_PAYLOAD];
};

/* Link Layer specification Section 2.3, Core 4.1 pages 2508 */
struct __attribute__ ((packed)) ll_pdu_scan_req {
	uint8_t scana[6];
	uint8_t adva[6];
};

/* Connection flags, used to keep track of various events and procedures in
 * a connection */
#define LL_CONN_FLAGS_ESTABLISHED	1	/* conn. created/established */

/** This structure contains all the fields needed to establish and maintain a
 * connection, on Master or Slave side. For a Master involved in multiple
 * simultaneous connections, there must be one structure per connection.
 *
 * Note that several parameters : conn interval, slave latency, supervision
 * timeout and channel map are defined for all connections in ll_conn_params
 * structure.
 *
 * See Link Layer specification Section 4.5, Core 4.1 pages 2537-2547*/
struct ll_conn_context {
	uint32_t	access_address;	/**< Access Address */
	uint32_t	crcinit;	/**< CRC init. value (3 bytes) */
	uint8_t		hop;		/**< hopIncrement for ch. selection */
	uint8_t		last_unmap_ch;	/**< last unmapped channel used */
	uint16_t	conn_event_cnt;	/**< Connection Event counter */
	uint16_t	superv_tmr;	/**< Connection supervision timer */
	uint8_t 	sn;		/**< transmitSeqNum for ack. */
	uint8_t		nesn;		/**< nextExpectedSeqNum for ack. */
	uint8_t	*	tx_buffer;	/**< TX buffer, handled in app. */
	uint8_t		tx_length;	/**< Nb of used bytes in TX buffer */
	uint8_t	*	rx_buffer;	/**< RX buffer, handled in app. */
	uint8_t		rx_length;	/**< Nb of used bytes in RX buffer */
	uint32_t	flags; 		/**< conn. flags, see LL_CONN_FLAGS_* */
};

static const bdaddr_t *laddr;
static ll_states_t current_state;

#define ADV_CH_IDX_37		0
#define ADV_CH_IDX_38		1
#define ADV_CH_IDX_39		2

static uint8_t adv_chs[] = { 37, 38, 39 };
static uint8_t adv_ch_idx;
static uint8_t prev_adv_ch_idx;
static uint8_t adv_ch_map;

/* Connection state channel map, 37 channels may be used
 * Must not be modified directly, use function ll_set_data_ch_map() instead */
static uint64_t data_ch_map;
/* The number of used channels and the used channels table are computed only
 * once by ll_set_data_ch_map() to speed up channel selection */
static uint8_t data_ch_nb;
static uint8_t data_ch_used[37];

static uint32_t t_adv_pdu_interval;
static uint32_t t_scan_window;

static struct ll_pdu_adv pdu_adv;
static struct ll_pdu_adv pdu_scan_rsp;

static bool rx = false;
static ll_conn_params_t ll_conn_params;
/*Internal pointer to an array of accepted peer addresses */
static bdaddr_t *ll_peer_addresses;
static uint16_t ll_num_peer_addresses; /*Size of the accepter peers array */

/** Timers used by the LL
 * Three timers are shared for the various states : one for triggering
 * events at periodic intervals (advertising start / scanning start)
 *
 * The second is used as single shot : change advertising channel or stop
 * scanning at the end of the window
 *
 * The third one is used to timeout when the link layer sends a packet and
 * waits the reply after an inter frame space.
 */
static int16_t t_ll_interval;
static int16_t t_ll_single_shot;
static int16_t t_ll_ifs;

static void t_ll_ifs_cb(void)
{
	radio_stop();
}

/** Callback function to report advertisers (SCANNING state) */
static adv_report_cb_t ll_adv_report_cb = NULL;

static __inline void send_scan_rsp(const struct ll_pdu_adv *pdu)
{
	struct ll_pdu_scan_req *scn;

	/* Start replying as soon as possible, if there is something wrong,
	 * cancel it.
	 */
	radio_send((const uint8_t *) &pdu_scan_rsp, 0);

	/* SCAN_REQ payload: ScanA(6 octets)|AdvA(6 octects) */
	if (pdu->length != 12)
		goto stop;

	if (pdu->rx_add != laddr->type)
		goto stop;

	scn = (struct ll_pdu_scan_req *) pdu->payload;

	if (memcmp(scn->adva, laddr->addr, 6))
		goto stop;

	return;

stop:
	radio_stop();
}

/* Check if the specified address is in the accepted peer addresses */
static __inline bool is_addr_accepted(uint8_t addr_type, uint8_t *addr)
{
	bool result = false;

	for(int i = 0; i < ll_num_peer_addresses; i++)
	{
		result = ((ll_peer_addresses+i)->type == addr_type
				&& !memcmp(addr, (ll_peer_addresses+i)->addr,
								BDADDR_LEN));
		if(result)
			break;
	}

/*	if(result)
		DBG("Address %02x:%02x:%02x:%02x:%02x:%02x accepted", addr[0],
				addr[1], addr[2], addr[3], addr[4], addr[5]);
	else
		DBG("Address %02x:%02x:%02x:%02x:%02x:%02x rejected", addr[0],
				addr[1], addr[2], addr[3], addr[4], addr[5]);
*/
	return result;
}

/* Check if the specified address is mine */
static __inline bool is_addr_mine(uint8_t addr_type, uint8_t *addr)
{
	bool result = (laddr->type == addr_type
	&& !memcmp(addr, laddr->addr, BDADDR_LEN));

/*	if(result)
		DBG("Address %02x:%02x:%02x:%02x:%02x:%02x is mine", addr[0],
				addr[1], addr[2], addr[3], addr[4], addr[5]);
	else
		DBG("Address %02x:%02x:%02x:%02x:%02x:%02x is not mine", addr[0],
				addr[1], addr[2], addr[3], addr[4], addr[5]);
*/
	return result;
}

/**@brief Function called by the radio driver (PHY layer) on packet RX
 * Dispatch the event according to the LL state
 */
static void ll_on_radio_rx(const uint8_t *pdu, bool crc, bool active)
{
	struct ll_pdu_adv *rcvd_pdu = (struct ll_pdu_adv*) pdu;

	switch(current_state) {
		case LL_STATE_SCANNING:
			if(!ll_adv_report_cb) {
				ERROR("No adv. report callback defined");
				return;
			}

			/* Extract information from PDU and call
			 * ll_adv_report_cb
			 */

			ll_adv_report_cb(rcvd_pdu->type, rcvd_pdu->tx_add,
						rcvd_pdu->payload,
						rcvd_pdu->length - BDADDR_LEN,
						rcvd_pdu->payload + BDADDR_LEN);

			/* Receive new packets while the radio is not explicitly
			 * stopped
			 */
			radio_recv(0);
			break;

		case LL_STATE_ADVERTISING:
			if (pdu_adv.type != LL_PDU_ADV_IND &&
					pdu_adv.type != LL_PDU_ADV_SCAN_IND)
				break;

			if (rcvd_pdu->type != LL_PDU_SCAN_REQ)
				break;

			timer_stop(t_ll_ifs);
			send_scan_rsp(rcvd_pdu);

			break;

		case LL_STATE_INITIATING:
			/*Answer to ADV_IND (connectable undirected advertising
			event) and ADV_DIRECT_IND (connectable directed
			advertising event) PDUs from accepted addresses with a
			CONNECT_REQ PDU */

			/* See Link Layer specification Section 2.3, Core 4.1
			 * page 2505 */
			if( (rcvd_pdu->type == LL_PDU_ADV_IND
				&& is_addr_accepted(rcvd_pdu->tx_add,
							rcvd_pdu->payload))
			|| (rcvd_pdu->type == LL_PDU_ADV_DIRECT_IND
				&& is_addr_accepted(rcvd_pdu->tx_add,
							rcvd_pdu->payload)
				&& is_addr_mine(rcvd_pdu->rx_add,
						rcvd_pdu->payload+BDADDR_LEN)) )
			{
				/*TODO send CONNECT_REQ PDU
				TODO go to CONNECTION_MASTER state
				TODO notify application (cb function) */
			}
			break;

		case LL_STATE_CONNECTION:
			/* Not implemented */
		case LL_STATE_STANDBY:
		default:
			/* Nothing to do */
			return;
	}
}

static void ll_on_radio_tx(bool active)
{
	timer_start(t_ll_ifs, T_IFS, t_ll_ifs_cb);
}

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
	if ((adv_ch_map & LL_ADV_CH_38) && (adv_ch_idx == ADV_CH_IDX_37))
		adv_ch_idx = ADV_CH_IDX_38;
	else if ((adv_ch_map & LL_ADV_CH_39) && (adv_ch_idx < ADV_CH_IDX_39))
		adv_ch_idx = ADV_CH_IDX_39;
	else
		return -1;

	return 0;
}

/**@brief Function that implement the Data channel index selection
 * Used in connection states to determine the BLE channel to use for the next
 * connection event.
 *
 * See Link Layer specification Section 4.5.8, Core v4.1 p.2544
 *
 * @param[in,out] unmapped_channel: a pointer to a variable containing the
 *	lastUnmappedChannel defined in LL spec. This variable will be updated
 * 	to store the new unmappedChannel.
 * @param[in] hop: the hopIncrement defined in LL spec (increment between 2
 * 	unmapped channels)
 *
 * @return the data channel index to use for the next connection event, according
 * 	to the global channel map data_ch_map.
 */
static __inline__ uint8_t data_ch_idx_selection(uint8_t *unmapped_channel,
								uint8_t hop)
{
	*unmapped_channel = (*unmapped_channel + hop) % 37;

	/* Return unmapped_channel if it is an used channel (1 in the ch. map)*/
	if( data_ch_map & ((uint64_t)1UL << (*unmapped_channel)) )
		return (*unmapped_channel);

	else
		return data_ch_used[(*unmapped_channel) % data_ch_nb];
}

/** Callback function for the "single shot" LL timer
 */
static void t_ll_single_shot_cb(void)
{
	switch(current_state) {
		case LL_STATE_ADVERTISING:
			radio_stop();
			radio_prepare(adv_chs[adv_ch_idx],
					LL_ACCESS_ADDRESS_ADV, LL_CRCINIT_ADV);
			radio_send((uint8_t *) &pdu_adv,
						rx ? RADIO_FLAGS_RX_NEXT : 0);

			prev_adv_ch_idx = adv_ch_idx;
			if (!inc_adv_ch_idx())
				timer_start(t_ll_single_shot,
							t_adv_pdu_interval,
							t_ll_single_shot_cb);
			break;

		case LL_STATE_SCANNING:
		case LL_STATE_INITIATING:
			/* Called at the end of the scan window */
			radio_stop();
			break;

		case LL_STATE_CONNECTION:
			/* Not implemented */
		case LL_STATE_STANDBY:
		default:
			/* Nothing to do */
			return;
	}
}

/** Callback function for the "interval" LL timer
 */
static void t_ll_interval_cb(void)
{
	switch(current_state) {
		case LL_STATE_ADVERTISING:
			adv_ch_idx = first_adv_ch_idx();
			t_ll_single_shot_cb();
			break;

		case LL_STATE_SCANNING:
		case LL_STATE_INITIATING:
			if(!inc_adv_ch_idx())
				adv_ch_idx = first_adv_ch_idx();

			radio_prepare(adv_chs[adv_ch_idx],
					LL_ACCESS_ADDRESS_ADV, LL_CRCINIT_ADV);
			radio_recv(0);
			timer_start(t_ll_single_shot, t_scan_window,
							t_ll_single_shot_cb);
			break;

		case LL_STATE_CONNECTION:
			/* Not implemented */
		case LL_STATE_STANDBY:
		default:
			/* Nothing to do */
			return;
	}
}

int16_t ll_advertise_start(ll_pdu_t type, uint32_t interval, uint8_t chmap)
{
	int16_t err_code;

	if (current_state != LL_STATE_STANDBY)
		return -ENOREADY;

	if (!chmap || (chmap & !LL_ADV_CH_ALL))
		return -EINVAL;

	if (interval % LL_ADV_INTERVAL_QUANTUM)
		return -EINVAL;

	if (interval < LL_ADV_INTERVAL_MIN_NONCONN
					|| interval > LL_ADV_INTERVAL_MAX)
			return -EINVAL;

	adv_ch_map = chmap;

	switch (type) {
	case LL_PDU_ADV_IND:
	case LL_PDU_ADV_SCAN_IND:
		rx = true;
		break;

	case LL_PDU_ADV_NONCONN_IND:
		rx = false;
		break;

	case LL_PDU_ADV_DIRECT_IND:
		/* TODO: Not implemented */
	default:
		/* Invalid PDU */
		return -EINVAL;
	}

	pdu_adv.type = type;
	t_adv_pdu_interval = TIMER_MILLIS(10); /* <= 10ms Sec 4.4.2.6 */

	radio_set_callbacks(rx ? ll_on_radio_rx : NULL,
						rx ? ll_on_radio_tx : NULL);

	DBG("PDU interval %u ms, event interval %u ms",
				t_adv_pdu_interval / 1000, interval / 1000);

	err_code = timer_start(t_ll_interval, interval, t_ll_interval_cb);
	if (err_code < 0)
		return err_code;

	current_state = LL_STATE_ADVERTISING;

	t_ll_interval_cb();

	return 0;
}

int16_t ll_advertise_stop()
{
	int16_t err_code;

	if (current_state != LL_STATE_ADVERTISING)
		return -ENOREADY;

	timer_stop(t_ll_ifs);

	err_code = timer_stop(t_ll_interval);
	if (err_code < 0)
		return err_code;

	err_code = timer_stop(t_ll_single_shot);
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

	pdu_scan_rsp.type = LL_PDU_SCAN_RSP;
	pdu_scan_rsp.tx_add = laddr->type;
	memcpy(pdu_scan_rsp.payload, laddr->addr, sizeof(laddr->addr));

	ll_set_scan_response_data(NULL, 0);
}

static void init_default_conn_params(void)
{
	ll_conn_params.conn_interval_min	= 16; /* 20 ms */
	ll_conn_params.conn_interval_max 	= 160; /* 200 ms */
	ll_conn_params.conn_latency 		= 0;
	ll_conn_params.supervision_timeout	= 100; /* 1s */
	ll_conn_params.minimum_ce_length	= 0;
	ll_conn_params.maximum_ce_length	= 16; /* 10 ms */

	ll_set_data_ch_map(0x1FFFFFFFFF); /* Use all channels */
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

	err_code = radio_init();
	if (err_code < 0)
		return err_code;

	t_ll_interval = timer_create(TIMER_REPEATED);
	if (t_ll_interval < 0)
		return t_ll_interval;

	t_ll_single_shot = timer_create(TIMER_SINGLESHOT);
	if (t_ll_single_shot < 0)
		return t_ll_single_shot;

	t_ll_ifs = timer_create(TIMER_SINGLESHOT);
	if (t_ll_ifs < 0)
		return t_ll_ifs;

	laddr = addr;
	current_state = LL_STATE_STANDBY;

	init_adv_pdus();
	init_default_conn_params();

	return 0;
}

/**@brief Set scan parameters and start scanning
 *
 * @note The HCI spec specifies interval in units of 0.625 ms.
 * 	Here we use us directly.
 *
 * @param [in] scan_type: should be LL_SCAN_ACTIVE or LL_SCAN_PASSIVE
 * 		(only the latter implemented at this time)
 * @param [in] interval: the scan Interval in us
 * @param [in] window: the scan Window in us
 * @param [in] adv_report_cb: the function to call for advertising report events
 *
 * @return -EINVAL if window > interval or interval > 10.24 s
 * @return -EINVAL if scan_type != LL_SCAN_PASSIVE
 */
int16_t ll_scan_start(uint8_t scan_type, uint32_t interval, uint32_t window,
						adv_report_cb_t adv_report_cb)
{
	int16_t err_code;

	if(window > interval || interval > LL_SCAN_INTERVAL_MAX)
		return -EINVAL;

	switch(scan_type) {
		case LL_SCAN_PASSIVE:
			/* Setup callback function */
			ll_adv_report_cb = adv_report_cb;
			break;

		case LL_SCAN_ACTIVE:
		/* Not implemented */
		default:
			return -EINVAL;
	}

	radio_set_callbacks(ll_on_radio_rx, NULL);

	/* Setup timer and save window length */
	t_scan_window = window;
	err_code = timer_start(t_ll_interval, interval, t_ll_interval_cb);
	if (err_code < 0)
		return err_code;

	current_state = LL_STATE_SCANNING;
	t_ll_interval_cb();

	DBG("interval %uus, window %uus", interval, window);

	return 0;
}

/**@brief Stop scanning
 */
int16_t ll_scan_stop(void)
{
	int16_t err_code;

	if (current_state != LL_STATE_SCANNING)
		return -ENOREADY;

	err_code = timer_stop(t_ll_interval);
	if (err_code < 0)
		return err_code;

	err_code = timer_stop(t_ll_single_shot);
	if (err_code < 0)
		return err_code;

	/* Call the single shot cb to stop the radio */
	t_ll_single_shot_cb();

	current_state = LL_STATE_STANDBY;

	DBG("");

	return 0;
}

/**@brief Set desired connection parameters
 *
 * @param [in] conn_params: a pointer to a new connection parameters struct
 */
int16_t ll_set_connection_params(ll_conn_params_t* conn_params)
{
	if(conn_params->conn_interval_max < conn_params->conn_interval_min)
	{
		ERROR("Min conn. interval must be lower than max interval");
		return -EINVAL;
	}

	if(conn_params->maximum_ce_length < conn_params->minimum_ce_length)
	{
		ERROR("Min CE length must be lower than max CE length");
		return -EINVAL;
	}

	/* TODO: check that the values are between min and max */
	ll_conn_params = *conn_params;

	return 0;
}

/**@brief Set data channel map to specify which channels can be used in connection
 * events.
 *
 * @param [in] ch_map: the new channel map ; every channel is represented by a bit
 * 	with the LSB being channel index 0 and the 36th bit data channel 36.
 * 	A 1 indicates that the channel is used.
 */
int16_t ll_set_data_ch_map(uint64_t ch_map)
{
	/* Mask to avoid channel indexes > 36 */
	ch_map &= (uint64_t)(0x1FFFFFFFFF);

	data_ch_map = ch_map;
	data_ch_nb = 0;

	/* Build remapping table (used indexes in acending order */
	for(uint8_t i = 0; i < 37; i++)
	{
		if(ch_map & ((uint64_t)1UL << i))
		{
			data_ch_used[data_ch_nb] = i;
			data_ch_nb++;
		}
	}

	if(data_ch_nb < 2)
	{
		ERROR("Invalid channel map : 0x%10x", data_ch_map);
		return -EINVAL;
	}

	return 0;
}


/**@brief Try to establish a connection with the specified peer
 *
 * @param [in] interval: the scanning interval in us (2.5ms -> 10.24s)
 * @param [in] window: the scanning window in us (2.5ms -> 10.24s)
 * @param [in] peer_addresses: a pointer to an array of Bluetooth addresses
 * 	to try to connect
 * @param [in] num_addresses: the size of the peer_addresses array
 */
int16_t ll_initiate_connection(uint32_t interval, uint32_t window,
	bdaddr_t* peer_addresses, uint16_t num_addresses)
{
	if(window > interval)
	{
		ERROR("interval must be greater than window");
		return -EINVAL;
	}
	if(peer_addresses == NULL || num_addresses == 0)
	{
		ERROR("at least one peer address must be specified");
		return -EINVAL;
	}

	ll_peer_addresses = peer_addresses;
	ll_num_peer_addresses = num_addresses;

	/* Initiating state :
	 * see Link Layer specification Section 4.4.4, Core v4.1 p.2537 */
	t_scan_window = window;
	int16_t err_code = timer_start(t_ll_interval, interval);
	if (err_code < 0)
		return err_code;

	current_state = LL_STATE_INITIATING;
	t_ll_interval_cb();

	DBG("interval %uus, window %uus", interval, window);

	return 0;
}
