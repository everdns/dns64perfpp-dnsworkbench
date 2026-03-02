/* dns64perf++ - C++14 DNS64 performance tester
 * Based on dns64perf by Gabor Lencse <lencse@sze.hu>
 * (http://ipv6.tilb.sze.hu/dns64perf/)
 * Copyright (C) 2017  Daniel Bakai <bakaid@kszk.bme.hu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

/** @file
 *  @brief Header for the DNS tester class
 */

#ifndef DNS_TESTER_H_INCLUDED_
#define DNS_TESTER_H_INCLUDED_

#include "dns.h"
#include "raii_socket.h"
#include "timer.h"
#include <chrono>
#include <exception>
#include <map>
#include <memory>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <string>
#include <vector>

static const size_t UDP_MAX_LEN = 512;

/**
 * One entry loaded from a dnsperf-format query file.
 */
struct QueryFileEntry {
  std::string name;              /**< The DNS name from the file */
  uint16_t qtype;                /**< The numeric query type */
  std::vector<uint8_t> packet;   /**< Pre-serialized DNS query packet (TX ID = 0) */
};

/**
 * Serialize a DNS query packet for the given name and qtype.
 * The TX ID field is written as 0x0000 (a placeholder).
 * Returns the serialized bytes.
 * Throws std::runtime_error if the name is too long or invalid.
 */
std::vector<uint8_t> serializeDnsQuery(const std::string &name, uint16_t qtype);

/**
 * Read a dnsperf-format file and return the list of QueryFileEntry objects.
 * Each line must be "<name> <type>".  Lines beginning with '#' or empty lines
 * are skipped.  Throws std::runtime_error on file-open failure or parse error.
 */
std::vector<QueryFileEntry> loadQueryFile(const std::string &path);

/**
 * An std::exception class for the DnsTester.
 */
class TestException : public std::exception {
private:
  std::string what_; /**< Exception string */
public:
  /**
   * A constructor.
   * @param what the exception string
   */
  TestException(std::string what);

  /**
   * A getter for the exception string.
   * @return the exception string
   */
  const char *what() const noexcept override;
};

/**
 * Class to represent one test query
 */
struct DnsQuery {
  uint16_t socket_index_; /**< Socket used to send query */
  std::chrono::high_resolution_clock::time_point
      time_sent_; /**< Timestamp of the send time */
  std::chrono::high_resolution_clock::time_point
      time_received_; /**< Timestamp of the receival */
  bool received_;     /**< Flag to mark whether an answer has been received */
  bool answered_;     /**< Flag to mark whether the answer was valid */
  std::chrono::nanoseconds rtt_; /**< Round-trip time of the query */

  DnsQuery(uint16_t socket_index);
};

/**
 * Class to represent a test
 */
class DnsTester {
private:
#ifdef DNS64PERFPP_IPV4
  struct sockaddr_in server_; /**< Address of the server */
#else
  struct sockaddr_in6 server_; /**< Address of the server */
#endif
  uint32_t num_req_;    /**< Number of requests */
  uint32_t num_thread_; /**< Number of threads */
  uint32_t thread_id_;  /**< Thread id of this tester */
  std::chrono::time_point<std::chrono::high_resolution_clock>
      test_start_time_; /**< Time to start the test */
  std::chrono::nanoseconds
      interval_ns_; /**< Interval between packets in nanoseconds (1e9 / QPS) */
  struct timeval timeout_;
  uint8_t query_data_[UDP_MAX_LEN]; /**< Array to store the packet */
  std::vector<QueryFileEntry> queries_; /**< Query list for this thread */
  uint32_t query_start_; /**< Index of first entry for this thread */
  std::vector<Socket>
      sockets_; /**< Sockets for sending and receiving queries */
  std::vector<struct pollfd> pollfds_; /**< Poll structures for sockets*/
  std::vector<DnsQuery> tests_;        /**< Test queries */
  uint32_t num_sent_;                  /**< Number of sent queries so far */
  uint32_t tx_to_query_[65536]; /**< Array mapping TX ID to query index (for in-flight requests) */
  std::mutex m_;                       /**< Mutex for accessing queries */
  std::vector<uint8_t> answer_data_;
  bool use_so_txtime_;                 /**< Whether to use SO_TXTIME for rate limiting */

  friend class DnsTesterAggregator;

  /**
   * Sends a burst
   */
  void test();

  /**
   * Receives an answer from a socket.
   * @param socket_index index of the socket
   */
  void receive(uint16_t socket_index);

public:
  /**
   * Constructor.
   * @param server_addr address of the server
   * @param port port of the server
   * @param queries list of query entries for this thread
   * @param num_req number of requests
   * @param num_thread total number of threads
   * @param thread_id this thread's ID
   * @param num_ports number of ports per thread
   * @param test_start_time when to start the test
   * @param interval_ns interval between packets in nanoseconds (calculated from QPS)
   * @param timeout socket timeout for receiving
   */
  DnsTester(
#ifdef DNS64PERFPP_IPV4
      struct in_addr server_addr,
#else
      struct in6_addr server_addr,
#endif
      uint16_t port, const std::vector<QueryFileEntry> &queries,
      uint32_t num_req, uint32_t num_thread, uint32_t thread_id,
      uint16_t num_ports,
      const std::chrono::time_point<std::chrono::high_resolution_clock>
          &test_start_time,
      std::chrono::nanoseconds interval_ns, struct timeval timeout);

  /**
   * Starts the test
   */
  void start();
};

class DnsTesterAggregator {
private:
  const std::vector<std::unique_ptr<DnsTester>> &dns_testers_;

public:
  /**
   * Constructor.
   * @param dns_testers DnsTesters to aggregate from
   */
  DnsTesterAggregator(
      const std::vector<std::unique_ptr<DnsTester>> &dns_testers);

  /**
   * Displays the aggregated test results
   */
  void display();

  /**
   * Writes the aggregated test results to a file.
   * @param filename the file to write to
   */
  void write(const char *filename);
};

#endif
