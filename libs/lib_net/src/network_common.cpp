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
#include "network_common.h"

#include <boost/asio.hpp>
#include <boost/array.hpp>
#include "network_types.h"
#include <iostream>
#include <string>

using boost::asio::ip::tcp;

boost::system::error_code
send_message_read_response(tcp::socket* s, message_t *msg, message_t *resp){
    boost::system::error_code error;
    error = send_message(s, msg);
    if(error.value() != boost::system::errc::success){
        std::cout << "Error sending message! " << error.message() << std::endl;
        return error;
    }
    return read_message(s, resp);
}

boost::system::error_code
read_message(tcp::socket* s, message_t *msg){
  boost::system::error_code error;
  boost::array<uint32_t, MESSAGE_HEADER_SIZE> buf;

  size_t len = boost::asio::read(*s, boost::asio::buffer(buf), error);
  if(error.value() != boost::system::errc::success){
    return error;
  }
  //std::cout << "Read " << std::dec << len << " bytes:" << buf[0] << " " << std::hex << buf[1] << " " << buf[2] << std::endl;
  msg->size_encrypted = buf[0];
  msg->size_plaintext = buf[1];
  msg->type = buf[2];
  msg->session_id = buf[3];

  if(msg->size_encrypted > 0){
    //Read data
    void *read_data = malloc(msg->size_encrypted);
    msg->data_encrypted = read_data;
    len = boost::asio::read(*s, boost::asio::buffer(msg->data_encrypted, msg->size_encrypted), error);
    //std::cout << "And additionally read " << len << " bytes as data." << std::endl;
  }

  if(error.value() != boost::system::errc::success){
    return error;
  }

  if(msg->size_plaintext > 0){
    //Read data
    void *read_plaintext = malloc(msg->size_plaintext);
    msg->data_plaintext = read_plaintext;
    len = boost::asio::read(*s, boost::asio::buffer(msg->data_plaintext, msg->size_plaintext), error);
    //std::cout << "And additionally read " << len << " bytes as data." << std::endl;
  }

  return error;

}

boost::system::error_code
send_message(tcp::socket* s, message_t *msg){
  boost::system::error_code error;
  boost::array<uint32_t, MESSAGE_HEADER_SIZE> out_buf = {msg->size_encrypted, msg->size_plaintext, msg->type, msg->session_id};
  int len = boost::asio::write(*s, boost::asio::buffer(out_buf), boost::asio::transfer_all() , error);
  if(error.value() != boost::system::errc::success){
    return error;
  }
  //std::cout << "Sent " << std::dec << len << " bytes:" << out_buf[0] << " " << std::hex << out_buf[1] << " " << out_buf[2]<< std::endl;

  //only send buffer if we want to and data is not null
  if(msg->size_encrypted > 0 && msg->data_encrypted){
    int len = boost::asio::write(*s, boost::asio::buffer(msg->data_encrypted, msg->size_encrypted), boost::asio::transfer_all(), error);
    //std::cout << "And additionally sent " << len << " bytes as data." << std::endl;
  }

  if(error.value() != boost::system::errc::success){
    return error;
  }

  //only send buffer if we want to and data is not null
  if(msg->size_plaintext > 0 && msg->data_plaintext){
    int len = boost::asio::write(*s, boost::asio::buffer(msg->data_plaintext, msg->size_plaintext), boost::asio::transfer_all(), error);
    //std::cout << "And additionally sent " << len << " bytes as data." << std::endl;
  }

  return error;
}
