/*
 * Copyright 2023, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>

#ifndef TEST_BUF_ALLOCATOR
#define TEST_BUF_ALLOCATOR

#define APF_TX_BUFFER_SIZE 1500

extern uint8_t apf_test_buffer[APF_TX_BUFFER_SIZE];
extern uint8_t apf_test_tx_packet[APF_TX_BUFFER_SIZE];
extern uint32_t apf_test_tx_packet_len;
extern uint8_t apf_test_tx_dscp;

#endif  // TEST_BUF_ALLOCATOR
