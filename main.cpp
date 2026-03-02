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

#include "dnstester.h"
#include <arpa/inet.h>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <memory>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>

int main(int argc, char *argv[]) {
#ifdef DNS64PERFPP_IPV4
  struct in_addr server_addr;
#else
  struct in6_addr server_addr;
#endif
  uint16_t port;
  uint32_t num_req, num_thread;
  uint16_t num_port;
  uint64_t qps;
  struct timeval timeout;
  if (argc < 8) {
    std::cerr << "Usage: dns64perfpp-workbench <server> <port> <query-file> <number of "
                 "requests> <number of threads> <number of ports "
                 "per thread> <QPS (queries per second)> <timeout in s>"
              << std::endl;
    return -1;
  }
/* Server address */
#ifdef DNS64PERFPP_IPV4
  if (inet_pton(AF_INET, argv[1], reinterpret_cast<void *>(&server_addr)) !=
      1) {
#else
  if (inet_pton(AF_INET6, argv[1], reinterpret_cast<void *>(&server_addr)) !=
      1) {
#endif
    std::cerr << "Bad server adddress." << std::endl;
    return -1;
  }
  /* Port */
  if (sscanf(argv[2], "%hu", &port) != 1) {
    std::cerr << "Bad port." << std::endl;
    return -1;
  }
  /* Load query file */
  std::string query_file = argv[3];
  std::vector<QueryFileEntry> queries;
  try {
    queries = loadQueryFile(query_file);
  } catch (const std::exception &e) {
    std::cerr << "Failed to load query file: " << e.what() << std::endl;
    return -1;
  }
  /* Number of requests */
  if (sscanf(argv[4], "%u", &num_req) != 1) {
    std::cerr << "Bad number of requests, must be between 0 and 2^32."
              << std::endl;
    return -1;
  }
  /* Number of threads */
  if (sscanf(argv[5], "%u", &num_thread) != 1) {
    std::cerr << "Bad number of threads size, must be between 0 and 2^32."
              << std::endl;
    return -1;
  }
  /* Number of ports per thread */
  if (sscanf(argv[6], "%hu", &num_port) != 1) {
    std::cerr << "Bad number of ports per thread, must be between 0 and 2^16."
              << std::endl;
    return -1;
  }
  /* QPS (queries per second) */
  if (sscanf(argv[7], "%lu", &qps) != 1 || qps == 0) {
    std::cerr << "Bad QPS, must be greater than 0." << std::endl;
    return -1;
  }
  /* Timeout */
  double timeout_, s, us;
  if (sscanf(argv[8], "%lf", &timeout_) != 1) {
    std::cerr << "Bad timeout." << std::endl;
    return -1;
  }
  us = modf(timeout_, &s) * 1000000;
  timeout.tv_sec = (time_t)s;
  timeout.tv_usec = (suseconds_t)us;

  std::vector<std::unique_ptr<DnsTester>> testers;
  std::vector<std::thread> threads;
  auto reference_time =
      std::chrono::high_resolution_clock::now() + std::chrono::seconds(2);

  /* Calculate per-packet interval from QPS (in nanoseconds) */
  uint64_t interval_ns = 1000000000ULL / qps;

  /* Split queries among threads */
  size_t queries_per_thread = queries.size() / num_thread;

  for (uint32_t i = 0; i < num_thread; i++) {
    /* Calculate start and end indices for this thread's queries */
    size_t start_idx = i * queries_per_thread;
    size_t end_idx = (i == num_thread - 1) ? queries.size() : (i + 1) * queries_per_thread;

    /* Create a subset of queries for this thread */
    std::vector<QueryFileEntry> thread_queries(
        queries.begin() + start_idx,
        queries.begin() + end_idx
    );

    testers.emplace_back(std::make_unique<DnsTester>(
        server_addr, port, thread_queries, num_req, num_thread, i,
        num_port,
        reference_time + std::chrono::nanoseconds{interval_ns / num_thread} * i,
        std::chrono::nanoseconds{interval_ns}, timeout));
  }
  try {
    for (uint32_t i = 0; i < num_thread; i++) {
      threads.emplace_back([&, i]() { testers[i]->start(); });
      pthread_setname_np(threads.back().native_handle(),
                         ("Receiver " + std::to_string(i)).c_str());
    }
    for (uint32_t i = 0; i < num_thread; i++) {
      threads[i].join();
    }
    DnsTesterAggregator aggregator(testers);
    aggregator.display();
    aggregator.write("dns64perf.csv");
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }
  return 0;
}
