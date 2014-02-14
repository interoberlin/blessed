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

#include <nrf51.h>
#include <nrf51_bitfields.h>
#include <app_timer.h>

#include <blessed/errcodes.h>
#include <blessed/timer.h>
#include <blessed/log.h>

/* nRF51 Series Reference Manual, section 18.1.2, page 101
 *
 * Prescaler for the Real Timer Counter (RTC). The prescaler defines the RTC
 * frequency. With 0, the RTC frequency assumes the maximum possible value:
 * 32768 kHz.
 */
#define PRESCALER			0
#define MAX_TIMERS			8
#define OP_QUEUE_SIZE			7

#define ERROR_HANDLING(err_code)					\
	switch (err_code) {						\
	case NRF_ERROR_INVALID_PARAM:					\
		return -EINVAL;						\
	case NRF_ERROR_INVALID_STATE:					\
		return -ENOREADY;					\
	case NRF_ERROR_NO_MEM:						\
		return -ENOMEM;						\
	default:							\
		return -EINTERN;					\
	}

/* Defines a buffer where both timers and timer operations will be stored.
 * This definition comes from app_timer.h.
 */
static uint32_t APP_TIMER_BUF[CEIL_DIV(APP_TIMER_BUF_SIZE(MAX_TIMERS,
				OP_QUEUE_SIZE + 1), sizeof(uint32_t))];

uint32_t timer_get_counter(void)
{
	return NRF_RTC1->COUNTER;
}

uint32_t timer_get_counter_max(void)
{
	return 0xFFFFFF;
}

int16_t timer_init(void)
{
	if (!NRF_CLOCK->EVENTS_LFCLKSTARTED) {
		NRF_CLOCK->LFCLKSRC = CLOCK_LFCLKSRC_SRC_Xtal
						<< CLOCK_LFCLKSRC_SRC_Pos;
		NRF_CLOCK->TASKS_LFCLKSTART = 1;
		while (!NRF_CLOCK->EVENTS_LFCLKSTARTED);
	}

	if (app_timer_init(PRESCALER, MAX_TIMERS, OP_QUEUE_SIZE + 1,
					APP_TIMER_BUF, NULL) != NRF_SUCCESS)
		return -EINTERN;

	return 0;
}

int16_t timer_create(uint8_t type, timer_cb cb)
{
	app_timer_mode_t mode;
	uint32_t err_code;
	uint32_t id;

	if (cb == NULL)
		return -EINVAL;

	switch (type) {
	case TIMER_SINGLESHOT:
		mode = APP_TIMER_MODE_SINGLE_SHOT;
		break;
	case TIMER_REPEATED:
		mode = APP_TIMER_MODE_REPEATED;
		break;
	default:
		return -EINVAL;
	}

	err_code = app_timer_create(&id, mode, cb);

	if (err_code == NRF_SUCCESS)
		return id;

	ERROR_HANDLING(err_code);
}

int16_t timer_start(int16_t id, uint32_t ms, void *user_data)
{
	uint32_t err_code;
	uint32_t ticks;

	if (id < 0)
		return -EINVAL;

	ticks = APP_TIMER_TICKS(ms, PRESCALER);

	err_code = app_timer_start(id, ticks, user_data);

	if (err_code == NRF_SUCCESS)
		return 0;

	ERROR_HANDLING(err_code);
}

int16_t timer_start_us(int16_t id, uint32_t us, void *user_data)
{
	uint32_t err_code;
	uint32_t ticks;

	if (id < 0)
		return -EINVAL;

	ticks = ROUNDED_DIV(APP_TIMER_TICKS(us, PRESCALER), 1000);

	err_code = app_timer_start(id, ticks, user_data);
	if (err_code == NRF_SUCCESS)
		return 0;

	ERROR_HANDLING(err_code);
}

int16_t timer_stop(int16_t id)
{
	uint32_t err_code;

	if (id < 0)
		return -EINVAL;

	err_code = app_timer_stop(id);

	if (err_code == NRF_SUCCESS)
		return 0;

	ERROR_HANDLING(err_code);
}
