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
#include <blessed/random.h>
#include <blessed/events.h>

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
	LL_STATE_CONNECTION_MASTER,
	LL_STATE_CONNECTION_SLAVE,
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

/* Link Layer specification Section 2.4.2, Core 4.1 page 2512 */
typedef enum ll_llid {
	LL_PDU_DATA_FRAG_EMPTY = 1,	/* Data PDU fragment or Empty PDU */
	LL_PDU_DATA_START_COMPLETE,	/* Complete Data PDU / 1st fragment */
	LL_PDU_CONTROL			/* LL Control PDU */
} ll_llid_t;

/* Link Layer specification Section 2.4, Core 4.1 page 2511 */
struct __attribute__ ((packed)) ll_pdu_data {
	uint8_t		llid:2;		/* See ll_llid_t */
	uint8_t		nesn:1;		/* Next expected sequence number */
	uint8_t		sn:1;		/* Sequence number */
	uint8_t		md:1;		/* More Data bit */
	uint8_t		_rfu_0:3;	/* Reserved for future use */

	uint8_t		length:5;	/* 0 <= payload length <= 31 */
	uint8_t		_rfu_1:3;	/* Reserved for future use */

	uint8_t		payload[LL_DATA_MTU_PAYLOAD];

	uint8_t		mic[LL_DATA_MIC_LEN];	/* Message Integrity Check */
};

/* Link Layer specification Section 2.3, Core 4.1 pages 2508 */
struct __attribute__ ((packed)) ll_pdu_scan_req {
	uint8_t scana[6];
	uint8_t adva[6];
};

/* Link Layer specification Section 2.3.3.1, Core 4.1 page 2509
 * CONNECT_REQ PDU payload */
struct __attribute__ ((packed)) ll_pdu_connect_payload {
	uint8_t		init_add[BDADDR_LEN];	/* Initiator address */
	uint8_t		adv_add[BDADDR_LEN];	/* Advertiser address */
	uint32_t	aa;			/* connection Access Address */
	uint8_t		crc_init[3];		/* connection CRC init */
	uint8_t		win_size;		/* tx window size (*1.25ms) */
	uint16_t	win_offset;		/* tx window offset (*1.25ms) */
	uint16_t	interval;		/* conn. interval (*1.25ms) */
	uint16_t	latency;		/* conn. slave latency */
	uint16_t	timeout;		/* conn. supervision (*10ms) */
	uint8_t		ch_map[5];		/* channel map */
	uint8_t		hop:5;			/* hop increment */
	uint8_t		sca:3;			/* Master sleep clock accuracy */
};

/* Connection flags, used to keep track of various events and procedures in
 * a connection */
#define LL_CONN_FLAGS_ESTABLISHED	1	/* conn. created/established */
#define LL_CONN_FLAGS_TERM_LOCAL	2	/* termination req by Host */
#define LL_CONN_FLAGS_TERM_PEER		4	/* term. req by peer device */

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
static struct ll_pdu_adv pdu_connect_req;
/* Outgoing packets for Connection state. Keep 1 packet per connection to allow
 * re-sending old data packets in case of bad CRC or flow control. */
static struct ll_pdu_data pdu_data_tx[LL_MAX_SIMULTANEOUS_CONNECTIONS];

static bool rx = false;
static ll_conn_params_t ll_conn_params;
static struct ll_conn_context ll_conn_contexts[LL_MAX_SIMULTANEOUS_CONNECTIONS];
static uint8_t ll_num_connections = 0;
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

/* Forward-declarations */
static void t_ll_interval_cb(void);

/** Callback function to report advertisers (SCANNING state) */
static adv_report_cb_t ll_adv_report_cb = NULL;

/** Callback function to report connection events (CONNECTION state) */
static conn_evt_cb_t ll_conn_evt_cb = NULL;
static uint8_t ll_conn_evt_params[BLE_EVT_PARAMS_MAX_SIZE];

/* Forward-declarations */
static void ll_on_radio_tx(bool active);

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

/**@brief Generate an appropriate, random Access Address following rules in
 * Link Layer specification Section 2.1.2, Core 4.1 pages 2503-2504
 */
static uint32_t generate_access_address(void)
{
	uint32_t aa = 0;
	do {
		for(int i = 0; i < 4; i++)
			aa |= (random_generate() << (8*i));
	} while(aa == LL_ACCESS_ADDRESS_ADV);
	/* TODO: check for the various other requirements in the spec */

	return aa;
}


/**@brief Prepare the next Data Channel PDU to send in a connection.
 *
 * Use the tx_buffer and tx_len in ll_conn_contexts[conn_index].
 *
 * @param[in] conn_index: the connection index in case of multiple connections
 * @param[in] control_pdu: if true, will issue a LL Control PDU with opCode
 * 	LL_UNKNOWN_RSP (to answer to a received LL Control PDU) instead of a
 * 	LL Data PDU
 * @param[in] control_pdu_opcode: the opCode of the received LL Control PDU
 */
static void prepare_next_data_pdu(uint8_t conn_index, bool control_pdu,
						uint8_t control_pdu_opcode)
{
	pdu_data_tx[conn_index].nesn = ll_conn_contexts[conn_index].nesn;
	pdu_data_tx[conn_index].sn = ll_conn_contexts[conn_index].sn;
	/* We assume that the master will send only 1 packet in every CE */
	pdu_data_tx[conn_index].md = 0UL;

	if(ll_conn_contexts[conn_index].flags & LL_CONN_FLAGS_TERM_LOCAL)
	{
		/* If a termination has been requested locally, send only
		 * LL_TERMINATE_IND PDUs until receiving an ack */
		pdu_data_tx[conn_index].llid = LL_PDU_CONTROL;
		pdu_data_tx[conn_index].length = 2;
		pdu_data_tx[conn_index].payload[0] = LL_TERMINATE_IND;
		/* REMOTE USER TERMINATED CONNECTION error code */
		pdu_data_tx[conn_index].payload[1] = 0x13;

	}
	else if(control_pdu)
	{
		/* Reply immediately to LL Control PDUs
		 * Link Layer spec, Section 2.4.2, Core 4.1 p. 2512-2521
		 * Link Layer spec, Section 5.1, Core 4.1 p. 2549-2568 */
		pdu_data_tx[conn_index].llid = LL_PDU_CONTROL;
		switch(control_pdu_opcode) {
		case LL_VERSION_IND:
			/* TODO test endianness */
			pdu_data_tx[conn_index].length = 6;
			pdu_data_tx[conn_index].payload[0] = LL_VERSION_IND;
			pdu_data_tx[conn_index].payload[1] = LL_VERS_NR;
			pdu_data_tx[conn_index].payload[2] =
						(uint8_t)(0xFF & LL_COMP_ID);
			pdu_data_tx[conn_index].payload[3] =
					(uint8_t)(0xFF & (LL_COMP_ID>>8));
			pdu_data_tx[conn_index].payload[4] =
					(uint8_t)(0xFF & LL_SUB_VERS_NR);
			pdu_data_tx[conn_index].payload[5] =
					(uint8_t)(0xFF & (LL_SUB_VERS_NR>>8));
			break;
		case LL_TERMINATE_IND:
			/* Send Empty Data PDU then stop connection */
			pdu_data_tx[conn_index].llid = LL_PDU_DATA_FRAG_EMPTY;
			pdu_data_tx[conn_index].length = 0;

			ll_conn_contexts[conn_index].flags |=
							LL_CONN_FLAGS_TERM_PEER;
			break;
		default:
			/* Reply with an LL_UNKNOWN_RSP PDU to all other,
			 * unsupported LL Control PDUs */
			pdu_data_tx[conn_index].length = 2;
			pdu_data_tx[conn_index].payload[0] = LL_UNKNOWN_RSP;
			pdu_data_tx[conn_index].payload[1] = control_pdu_opcode;
		}
	}
	else if(ll_conn_contexts[conn_index].tx_length > 0)
	{
		/* There is new data to send */
		pdu_data_tx[conn_index].llid = LL_PDU_DATA_START_COMPLETE;
		pdu_data_tx[conn_index].length =
					ll_conn_contexts[conn_index].tx_length;
		memcpy(pdu_data_tx[conn_index].payload,
					ll_conn_contexts[conn_index].tx_buffer,
					ll_conn_contexts[conn_index].tx_length);

		/* Data in the TX buffer is now outdated */
		ll_conn_contexts[conn_index].tx_length = 0;

		/* Notify upper layers that data has been sent */
		ble_evt_ll_packets_sent_t *packets_tx_params =
				(ble_evt_ll_packets_sent_t*)ll_conn_evt_params;
		packets_tx_params->index = conn_index;
		ll_conn_evt_cb(BLE_EVT_LL_PACKETS_SENT, ll_conn_evt_params);
	}
	else
	{
		/* No new data => send Empty Data PDU */
		pdu_data_tx[conn_index].llid = LL_PDU_DATA_FRAG_EMPTY;
		pdu_data_tx[conn_index].length = 0;
	}
}

/**@brief Handle the end of a connection, which can be caused by various reasons
 *
 * @param[in] conn_index: the index in case of multiple connections
 * @param[in] reason: an error code indicating why the connection is being
 * 	closed.
 */
static void end_connection(uint8_t conn_index, uint8_t reason)
{
	//TODO handle connection index.

	current_state = LL_STATE_STANDBY;
	ll_num_connections--;

	/* Notify upper layers */
	ble_evt_ll_disconnect_complete_t *disconn_params =
			(ble_evt_ll_disconnect_complete_t*)ll_conn_evt_params;
	disconn_params->index = conn_index;
	disconn_params->reason = reason;
	ll_conn_evt_cb(BLE_EVT_LL_DISCONNECT_COMPLETE, ll_conn_evt_params);
}

/**@brief Function called by the radio driver (PHY layer) on packet RX
 * Dispatch the event according to the LL state
 */
static void ll_on_radio_rx(const uint8_t *pdu, bool crc, bool active)
{
	struct ll_pdu_adv *rcvd_adv_pdu;
	struct ll_pdu_data *rcvd_data_pdu;
	ble_evt_ll_connection_complete_t *conn_complete_params =
			(ble_evt_ll_connection_complete_t*)ll_conn_evt_params;
	ble_evt_ll_packets_received_t *packets_rx_params =
			(ble_evt_ll_packets_received_t*)ll_conn_evt_params;

	switch(current_state) {
		case LL_STATE_SCANNING:
			if(!ll_adv_report_cb) {
				ERROR("No adv. report callback defined");
				return;
			}

			/* Extract information from PDU and call
			 * ll_adv_report_cb
			 */
			rcvd_adv_pdu = (struct ll_pdu_adv*) pdu;

			ll_adv_report_cb(rcvd_adv_pdu->type,
					rcvd_adv_pdu->tx_add,
					rcvd_adv_pdu->payload,
					rcvd_adv_pdu->length - BDADDR_LEN,
					rcvd_adv_pdu->payload + BDADDR_LEN);

			/* Receive new packets while the radio is not explicitly
			 * stopped
			 */
			radio_recv(0);
			break;

		case LL_STATE_ADVERTISING:
			rcvd_adv_pdu = (struct ll_pdu_adv*) pdu;

			if (pdu_adv.type != LL_PDU_ADV_IND &&
					pdu_adv.type != LL_PDU_ADV_SCAN_IND)
				break;

			if (rcvd_adv_pdu->type != LL_PDU_SCAN_REQ)
				break;

			timer_stop(t_ll_ifs);
			send_scan_rsp(rcvd_adv_pdu);

			break;

		case LL_STATE_INITIATING:
			/*Answer to ADV_IND (connectable undirected advertising
			event) and ADV_DIRECT_IND (connectable directed
			advertising event) PDUs from accepted addresses with a
			CONNECT_REQ PDU */
			rcvd_adv_pdu = (struct ll_pdu_adv *)(pdu);
			/* See Link Layer specification Section 2.3, Core 4.1
			 * page 2505 */
			if( (rcvd_adv_pdu->type == LL_PDU_ADV_IND
				&& is_addr_accepted(rcvd_adv_pdu->tx_add,
							rcvd_adv_pdu->payload))
			|| (rcvd_adv_pdu->type == LL_PDU_ADV_DIRECT_IND
				&& is_addr_accepted(rcvd_adv_pdu->tx_add,
							rcvd_adv_pdu->payload)
				&& is_addr_mine(rcvd_adv_pdu->rx_add,
					rcvd_adv_pdu->payload+BDADDR_LEN)) )
			{
				timer_stop(t_ll_single_shot);
				timer_stop(t_ll_interval);

				/* Complete CONNECT_REQ PDU with the
				 * advertiser's address
				 */
				pdu_connect_req.rx_add = rcvd_adv_pdu->tx_add;
				memcpy(pdu_connect_req.payload+BDADDR_LEN,
					rcvd_adv_pdu->payload, BDADDR_LEN);

				current_state = LL_STATE_CONNECTION_MASTER;

				timer_start(t_ll_interval,
					ll_conn_params.conn_interval_min*1250,
							t_ll_interval_cb);

				radio_set_callbacks(ll_on_radio_rx,
								ll_on_radio_tx);

				/* Prepare the Data PDU that will be sent */
				prepare_next_data_pdu(0, false, 0x00);

				/* Send an event to the upper layers */
				conn_complete_params->index = 0;
				conn_complete_params->peer_addr.type =
							rcvd_adv_pdu->tx_add;
				memcpy(conn_complete_params->peer_addr.addr,
					rcvd_adv_pdu->payload, BDADDR_LEN);

				ll_conn_evt_cb(BLE_EVT_LL_CONNECTION_COMPLETE,
							ll_conn_evt_params);
			}
			else
			{
				radio_stop();
				radio_recv(RADIO_FLAGS_TX_NEXT);
			}

			break;

		case LL_STATE_CONNECTION_MASTER:
			/* Receive a data PDU */
			rcvd_data_pdu = (struct ll_pdu_data *)(pdu);

			timer_stop(t_ll_ifs);

			ll_conn_contexts[0].superv_tmr = 0;
			ll_conn_contexts[0].flags |= LL_CONN_FLAGS_ESTABLISHED;

			/* Hypothesis for simplification : the connection event
			 * is closed when the slave has sent a packet,
			 * regardless of CRC match or MD bit. The master will
			 * only send one packet in each CE.
			 * See LL spec, section 4.5.6, Core 4.1 p.2542
			 */

			/* Ack/flow control according to :
			 * LL spec, section 4.5.9, Core 4.1 p. 2545 */
			if(!crc)
			{
				/* ignore incoming data
				 * equivalent to a NACK => resend the old data */
				DBG("Packet with bad CRC received");
				return;
			}

			if(rcvd_data_pdu->sn ==
					(ll_conn_contexts[0].nesn & 0x01))
			{
				/* New incoming Data Channel PDU
				* local NESN *may* be incremented to allow flow
				* control */
				ll_conn_contexts[0].nesn++;

				/* Get data if the received packet wasn't a
				 * LL Control PDU or an Empty PDU*/
				if(rcvd_data_pdu->llid != LL_PDU_CONTROL &&
						rcvd_data_pdu->length > 0)
				{
					ll_conn_contexts[0].rx_length =
							rcvd_data_pdu->length;
					memcpy(ll_conn_contexts[0].rx_buffer,
							rcvd_data_pdu->payload,
							rcvd_data_pdu->length);
					/* Send an event to upper layers to
					 * notify that new data is available */
					packets_rx_params->index = 0;
					packets_rx_params->length =
					ll_conn_contexts[0].rx_length;
					ll_conn_evt_cb(BLE_EVT_LL_PACKETS_RECEIVED,
							ll_conn_evt_params);

				}
			}
			else
			{
				/* Old incoming Data Channel PDU => ignore */
			}

			if(rcvd_data_pdu->nesn ==
						(ll_conn_contexts[0].sn & 0x01))
			{
				/* NACK => resend old data (do nothing) */
				DBG("NACK received");
			}
			else
			{
				/* ACK => send new data */
				ll_conn_contexts[0].sn++;

				/* If a terminating procedure has been requested
				 *  we can exit connection state now */
				if(ll_conn_contexts[0].flags &
						LL_CONN_FLAGS_TERM_PEER ) {
					end_connection(0,
						BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
					break;
				} else if(ll_conn_contexts[0].flags &
						LL_CONN_FLAGS_TERM_LOCAL ) {
					end_connection(0,
						BLE_HCI_LOCAL_HOST_TERMINATED_CONNECTION);
					break;
				}

				/* Prepare a new packet according to what was
				 * just received */
				if(rcvd_data_pdu->llid == LL_PDU_CONTROL)
					prepare_next_data_pdu(0, true,
						rcvd_data_pdu->payload[0]);
				else
					prepare_next_data_pdu(0, false, 0x00);

			}

			break;
		case LL_STATE_CONNECTION_SLAVE:
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

		case LL_STATE_CONNECTION_MASTER:
		case LL_STATE_CONNECTION_SLAVE:
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

			if(current_state == LL_STATE_INITIATING) {
				radio_recv(RADIO_FLAGS_TX_NEXT);
				radio_set_out_buffer((uint8_t*)&pdu_connect_req);
			} else
				radio_recv(0);

			timer_start(t_ll_single_shot, t_scan_window,
							t_ll_single_shot_cb);
			break;

		case LL_STATE_CONNECTION_MASTER:
			/* LL spec, section 4.5, Core v4.1 p.2537-2547
			 * LL spec, Section 2.4, Core 4.1 page 2511
			 */

			/* Handle supervision timer which is reset every time a
			 * new packet is received
			 * NOTE: this doesn't respect the spec as the timer's
			 * unit is connInterval
			 */
			if((!(ll_conn_contexts[0].flags & LL_CONN_FLAGS_ESTABLISHED) &&
					ll_conn_contexts[0].superv_tmr >= 6) ||
			((ll_conn_contexts[0].flags & LL_CONN_FLAGS_ESTABLISHED) &&
					ll_conn_contexts[0].superv_tmr >=
					(ll_conn_params.supervision_timeout /
					ll_conn_params.conn_interval_min)))
			{
				end_connection(0, BLE_HCI_CONNECTION_TIMEOUT);
				return;
			}

			radio_stop();
			radio_prepare(data_ch_idx_selection(
					&(ll_conn_contexts[0].last_unmap_ch),
					ll_conn_contexts[0].hop),
					ll_conn_contexts[0].access_address,
					ll_conn_contexts[0].crcinit);

			radio_send((uint8_t *)(&pdu_data_tx[0]),
							RADIO_FLAGS_RX_NEXT);

			ll_conn_contexts[0].conn_event_cnt++;
			ll_conn_contexts[0].superv_tmr++;

			/* Next step : ll_on_radio_rx (receive a packet from
			 * the slave) or t_ll_ifs_cb (RX timeout) */
			break;

		case LL_STATE_CONNECTION_SLAVE:
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

/**@brief Initialize the connection context structure at the beginning of a new
 * connection, and prepare the CONNECT_REQ PDU to send
 *
 * See Link Layer specification Section 4.5, Core 4.1 pages 2537-2547
 *
 * @param[in] conn_index: the connection index in case of multiple connections
 */
static void init_connection_context(uint8_t conn_index)
{
	struct ll_conn_context *context = &ll_conn_contexts[conn_index];
	context->access_address = generate_access_address();
	context->crcinit = 0;
	for(int i = 0; i < 3; i++)
		context->crcinit |= (random_generate() << (8*i));
	/* "Random" value between 5 and 16 */
	context->hop = (random_generate() * 11 / 255) + 5;
	context->last_unmap_ch = 0;
	/* The CE counter is incremented at each CE and must be 0 on the first
	 * CE */
	context->conn_event_cnt = 0xFFFF;
	context->superv_tmr = 0;
	context->sn = 0;
	context->nesn = 0;
	context->flags = 0;

	context->tx_buffer = NULL;
	context->tx_length = 0;
	context->rx_buffer = NULL;
	context->rx_length = 0;

	/* PDU initialization */
	struct ll_pdu_connect_payload *payload;

	pdu_connect_req.type = LL_PDU_CONNECT_REQ;
	pdu_connect_req.tx_add = laddr->type;
	pdu_connect_req.length = sizeof(*payload);

	payload = (struct ll_pdu_connect_payload*)(pdu_connect_req.payload);
	memcpy(payload->init_add, laddr->addr, BDADDR_LEN);

	payload->aa = context->access_address;
	for(int i = 0; i < 3; i++)
		payload->crc_init[i] = (uint8_t)(context->crcinit >> 8*i);

	/* Max. allowed value : min(10ms, connInterval-1.25ms) */
	if(ll_conn_params.conn_interval_min > 8)
		payload->win_size = 8;
	else
		payload->win_size = ll_conn_params.conn_interval_min-1;
	/* The interval timer is set to fire every conn_interval_min just
	 * after the CONNECT_REQ PDU is sent. We set the offset to
	 * conn_interval_min - 3 to keep a wide window almost centered on the
	 * first timer event.
	 */
	payload->win_offset = ll_conn_params.conn_interval_min-3;

	payload->interval = ll_conn_params.conn_interval_min;
	payload->latency = ll_conn_params.conn_latency;
	payload->timeout = ll_conn_params.supervision_timeout;
	for(int i = 0; i < 5; i++)
		payload->ch_map[i] = (uint8_t)(data_ch_map >> 8*i);

	payload->hop = context->hop;
	payload->sca = 0; /* Worst accuracy : 251->500ppm */

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

	err_code = random_init();
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
 * @param [out] rx_buf: a pointer to an array to store incoming data from the
 * 	peer device
 * @param [out] conn_evt_cb: the function to call on connection events
 */
int16_t ll_initiate_connection(uint32_t interval, uint32_t window,
	bdaddr_t* peer_addresses, uint16_t num_addresses, uint8_t* rx_buf,
						conn_evt_cb_t conn_evt_cb)
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

	if(ll_num_connections >= LL_MAX_SIMULTANEOUS_CONNECTIONS)
	{
		ERROR("only %u simultaneous connections allowed",
					LL_MAX_SIMULTANEOUS_CONNECTIONS);
		return -ENOMEM;
	}

	ll_peer_addresses = peer_addresses;
	ll_num_peer_addresses = num_addresses;
	ll_conn_evt_cb = conn_evt_cb;

	/* Generate new connection parameters and init CONNECT_REQ PDU */
	uint8_t conn_index = ll_num_connections;
	init_connection_context(conn_index);
	ll_conn_contexts[conn_index].rx_buffer = rx_buf;

	ll_num_connections++;

	radio_set_callbacks(ll_on_radio_rx, NULL);

	/* Initiating state :
	 * see Link Layer specification Section 4.4.4, Core v4.1 p.2537 */
	t_scan_window = window;
	int16_t err_code = timer_start(t_ll_interval, interval,
							t_ll_interval_cb);
	if (err_code < 0)
		return err_code;

	current_state = LL_STATE_INITIATING;
	t_ll_interval_cb();

	DBG("interval %uus, window %uus", interval, window);

	return 0;
}

/**@brief Stop the initiating procedure
 */
int16_t ll_initiate_cancel(void)
{
	if (current_state != LL_STATE_INITIATING)
		return -ENOREADY;

	timer_stop(t_ll_interval);
	timer_stop(t_ll_single_shot);
	timer_stop(t_ll_ifs);

	radio_stop();

	current_state = LL_STATE_STANDBY;

	DBG("");

	return 0;
}

/**@brief Set new data to send to the peer when in connection state
 *
 * @param[in] data: Pointer to a buffer containing the data to send
 * @param[in] len: The number of bytes to send. Must be <= 27
 * See Link Layer specification, Section 2.4, Core v4.1 p.2511
 */
int16_t ll_cnx_send_data(uint8_t *data, uint8_t len)
{
	if(len > LL_DATA_MTU_PAYLOAD)
	{
		ERROR("Max payload length : %u bytes in connection state",
							LL_DATA_MTU_PAYLOAD);
		return -EINVAL;
	}

	ll_conn_contexts[0].tx_buffer = data;
	ll_conn_contexts[0].tx_length = len;

	return 0;
}

/**@brief Terminate the current connection
 *
 */
int16_t ll_cnx_terminate(void)
{
	/* TODO check that we are in connection state */

	ll_conn_contexts[0].flags |= LL_CONN_FLAGS_TERM_LOCAL;
	/* Force the preparation of the next data PDU, discarding current
	 * operations */
	prepare_next_data_pdu(0, false, 0);

	return 0;
}
