/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _NET_APF_H_
#define _NET_APF_H_

#include <linux/types.h>

#define APF_FAMILY_NAME "net_apf"
#define APF_FAMILY_VERSION 1

enum apf_commands {
    APF_CMD_UNSPEC,
    APF_CMD_GET_INFO,
    APF_CMD_SET_ID,
    APF_CMD_ENABLE,
    APF_CMD_GET_RAM_SIZE,
    APF_CMD_READ,
    APF_CMD_WRITE,
    APF_CMD_DISABLE,
    APF_CMD_SET_FAST_PATH,
};

enum apf_attributes {
    APF_ATTR_UNSPEC,
    APF_ATTR_IFINDEX,
    APF_ATTR_INFO_VERSION,
    APF_ATTR_INFO_ID,
    APF_ATTR_INFO_TOTAL_RAM,
    APF_ATTR_INFO_USED_RAM,
    APF_ATTR_INFO_OVERHEAD,
    APF_ATTR_INFO_GRANULARITY,
    APF_ATTR_RAM_SIZE,
    APF_ATTR_OFFSET,
    APF_ATTR_DATA,
    APF_ATTR_DATA_LEN,
    APF_ATTR_FP_UCAST_MAC,
    APF_ATTR_FP_VLAN_TAG,
    APF_ATTR_FP_UCAST_ADDR4,
    APF_ATTR_FP_ENABLE_IPV6,
};

#endif /* _NET_APF_H_ */
