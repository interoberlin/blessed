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

#define TIMER_SINGLESHOT		0
#define TIMER_REPEATED			1

#define TIME_EXP(exp, result)						\
	do {								\
		uint32_t max;						\
		uint32_t before = timer_get_counter();			\
		exp;							\
		result = timer_get_counter();				\
		max = timer_get_counter_max();				\
		if (result >= before)					\
			result -= before;				\
		else							\
			result += (uint64_t) (max - before);		\
	} while (0)

typedef void (*timer_cb) (void *user_data);

int16_t timer_init(void);
int16_t timer_create(uint8_t type, timer_cb cb);
int16_t timer_start(int16_t id, uint32_t ms, void *user_data);
int16_t timer_start_us(int16_t id, uint32_t us, void *user_data);
int16_t timer_stop(int16_t id);

uint32_t timer_get_counter(void);
uint32_t timer_get_counter_max(void);
