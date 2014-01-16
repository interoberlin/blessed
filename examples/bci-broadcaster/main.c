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

#include "bluetooth.h"

#define BLE_ADDRESS_ADDR		{ 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00 }
#define BLE_ADDRESS_TYPE		BDADDR_TYPE_RANDOM
#define BLE_ADDRESS			{ BLE_ADDRESS_ADDR, BLE_ADDRESS_TYPE }

/* "Hello world from BLEStack!" */
static uint8_t data[] = { 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72,
				0x6C, 0x64, 0x20, 0x66, 0x72, 0x6F, 0x6D, 0x20,
				0x42, 0x4C, 0x45, 0x53, 0x74, 0x61, 0x63, 0x6B,
				0x21 };

int main(void)
{
	int16_t status;

	BLUETOOTH_INIT(status);

	if (status < 0)
		return status;

	bci_set_advertising_data(data, sizeof(data));
	bci_set_advertise_enable(ENABLE);

	while (1);

	return 0;
}
