/* Copyright (c) 2018 Aalto University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * common.h
 *
 *  Created on: Jul 21, 2017
 */

#ifndef NETWORK_NETWORK_COMMON_H_
#define NETWORK_NETWORK_COMMON_H_

#include <boost/asio.hpp>
#include "network_types.h"

using boost::asio::ip::tcp;

boost::system::error_code send_message_read_response(tcp::socket* s, message_t *msg, message_t *resp);
boost::system::error_code read_message(tcp::socket* s, message_t *msg);
boost::system::error_code send_message(tcp::socket* s, message_t *msg);

#endif /* NETWORK_NETWORK_COMMON_H_ */
