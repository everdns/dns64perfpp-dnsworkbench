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
#include "spin_sleep.hpp"
#include <arpa/inet.h>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <limits.h>
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <net/if.h>
#include <sstream>
#include <stdexcept>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

std::vector<uint8_t> serializeDnsQuery(const std::string &name,
                                          uint16_t qtype) {
  uint8_t buf[UDP_MAX_LEN];
  memset(buf, 0x00, sizeof(buf));

  // Header
  DNSHeader *header = reinterpret_cast<DNSHeader *>(buf);
  header->id(0);  // TX ID placeholder
  header->qr(0);
  header->opcode(DNSHeader::OpCode::Query);
  header->aa(false);
  header->tc(false);
  header->rd(true);
  header->ra(false);
  header->rcode(DNSHeader::RCODE::NoError);
  header->qdcount(1);
  header->ancount(0);
  header->nscount(0);
  header->arcount(0);

  // QNAME encoding
  uint8_t *p = buf + sizeof(DNSHeader);
  uint8_t *end = buf + sizeof(buf);

  // Append trailing '.' if not present
  std::string fqdn = name;
  if (fqdn.empty() || fqdn.back() != '.') fqdn += '.';

  // Use a local char array for strtok
  char tmp[512];
  if (fqdn.size() >= sizeof(tmp))
    throw std::runtime_error{"DNS name too long: " + name};
  memcpy(tmp, fqdn.c_str(), fqdn.size() + 1);

  char *label = strtok(tmp, ".");
  while (label != nullptr) {
    size_t lblen = strlen(label);
    if (lblen > 63)
      throw std::runtime_error{"Label too long in: " + name};
    if (p + 1 + lblen + 4 > end)  // +4 for qtype+qclass
      throw std::runtime_error{"DNS name too long to fit in UDP packet: " +
                               name};
    *p = static_cast<uint8_t>(lblen);
    p += 1;
    memcpy(p, label, lblen);
    p += lblen;
    label = strtok(nullptr, ".");
  }
  *p = 0x00;  // root label
  p += 1;

  // QTYPE and QCLASS
  *reinterpret_cast<uint16_t *>(p) = htons(qtype);
  p += sizeof(uint16_t);
  *reinterpret_cast<uint16_t *>(p) = htons(QClass::IN);
  p += sizeof(uint16_t);

  size_t len = static_cast<size_t>(p - buf);
  return std::vector<uint8_t>(buf, buf + len);
}
std::vector<QueryFileEntry> loadQueryFile(const std::string &path) {
  std::ifstream f(path);
  if (!f)
    throw std::runtime_error{"Cannot open query file: " + path};
  std::vector<QueryFileEntry> result;
  std::string line;
  size_t lineno = 0;
  while (std::getline(f, line)) {
    ++lineno;
    // strip trailing \r for Windows line endings
    if (!line.empty() && line.back() == '\r') line.pop_back();
    // skip blanks and comments
    if (line.empty() || line[0] == '#') continue;

    std::istringstream ss(line);
    std::string name, typestr;
    if (!(ss >> name >> typestr)) {
      throw std::runtime_error{"Query file parse error at line " +
                               std::to_string(lineno)};
    }
    uint16_t qtype;
    if (!parseQType(typestr, &qtype)) {
      throw std::runtime_error{"Unknown QType '" + typestr + "' at line " +
                               std::to_string(lineno)};
    }
    QueryFileEntry entry;
    entry.name = name;
    entry.qtype = qtype;
    entry.packet = serializeDnsQuery(name, qtype);
    result.push_back(std::move(entry));
  }
  if (result.empty())
    throw std::runtime_error{"Query file is empty: " + path};
  return result;
}

/**
 * Get current CLOCK_TAI time in nanoseconds.
 */
static uint64_t get_clock_tai_ns() {
  struct timespec ts;
  if (clock_gettime(CLOCK_TAI, &ts) < 0) {
    throw std::runtime_error{"clock_gettime(CLOCK_TAI) failed: " +
                             std::string(strerror(errno))};
  }
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/**
 * Send a UDP packet with SO_TXTIME scheduling.
 * Sends the packet to be transmitted at the specified txtime (in nanoseconds since CLOCK_TAI).
 */
static ssize_t sendto_with_txtime(
    int sockfd, const void *buf, size_t len, int flags,
    const struct sockaddr *dest_addr, socklen_t addrlen,
    uint64_t txtime_ns) {
  /* Build ancillary data for SO_TXTIME */
  char control_buf[CMSG_SPACE(sizeof(uint64_t))];
  memset(control_buf, 0, sizeof(control_buf));

  struct iovec iov;
  iov.iov_base = const_cast<void *>(buf);
  iov.iov_len = len;

  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_name = const_cast<struct sockaddr *>(dest_addr);
  msg.msg_namelen = addrlen;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control_buf;
  msg.msg_controllen = sizeof(control_buf);

  /* Add SO_TXTIME cmsg */
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_TXTIME;
  cmsg->cmsg_len = CMSG_LEN(sizeof(uint64_t));
  *(uint64_t *)CMSG_DATA(cmsg) = txtime_ns;

  return ::sendmsg(sockfd, &msg, flags);
}

TestException::TestException(std::string what) : what_{what} {}

const char *TestException::what() const noexcept { return what_.c_str(); }

DnsQuery::DnsQuery(uint16_t socket_index)
    : socket_index_{socket_index}, received_{false}, answered_{false},
      rtt_{std::chrono::nanoseconds{-1}} {}

DnsTester::DnsTester(
#ifdef DNS64PERFPP_IPV4
    struct in_addr server_addr,
#else
    struct in6_addr server_addr,
#endif
    uint16_t port, const std::vector<QueryFileEntry> &queries,
    uint32_t num_req, uint32_t num_thread, uint32_t thread_id,
    uint16_t num_ports, uint32_t batch_size, uint64_t min_sleep_ns,
    const std::chrono::time_point<std::chrono::high_resolution_clock>
        &test_start_time,
    std::chrono::nanoseconds interval_ns, struct timeval timeout)
    : num_req_{num_req / num_thread}, num_thread_{num_thread},
      thread_id_{thread_id}, test_start_time_{test_start_time},
      interval_ns_{interval_ns}, timeout_{timeout}, queries_{queries},
      num_sent_{0}, use_so_txtime_{true}, batch_size_{batch_size},
      min_sleep_ns_{min_sleep_ns} {
  /* Initialize tx_to_query_ array */
  std::fill(std::begin(tx_to_query_), std::end(tx_to_query_), UINT32_MAX);
  /* Reserve space for answer data */
  answer_data_.resize(UDP_MAX_LEN);
  /* Calculate query start index */
  query_start_ = thread_id_ * num_req_;
  /* Fill server sockaddr structure */
  memset(&server_, 0x00, sizeof(server_));
#ifdef DNS64PERFPP_IPV4
  server_.sin_family = AF_INET;
  server_.sin_addr = server_addr;
  server_.sin_port = htons(port);
#else
  server_.sin6_family = AF_INET6;
  server_.sin6_addr = server_addr;
  server_.sin6_port = htons(port);
#endif
  /* Bind sockets */
  uint16_t base_port = 10000U;
  while (sockets_.size() < (num_ports == 0U ? 1U : num_ports)) {
    /* Create socket */
    int sockfd;
#ifdef DNS64PERFPP_IPV4
    if ((sockfd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
#else
    if ((sockfd = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
#endif
      std::stringstream ss;
      ss << "Cannot create socket: " << strerror(errno);
      throw TestException{ss.str()};
    }
      /* Bind socket */
#ifdef DNS64PERFPP_IPV4
    struct sockaddr_in local_addr;
    memset(&local_addr, 0x00, sizeof(local_addr));
    local_addr.sin_family = AF_INET;                // IPv4
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY); // To any valid IP address
    local_addr.sin_port = htons(base_port++);       // Get a new port
#else
    struct sockaddr_in6 local_addr;
    memset(&local_addr, 0x00, sizeof(local_addr));
    local_addr.sin6_family = AF_INET6;         // IPv6
    local_addr.sin6_addr = in6addr_any;        // To any valid IP address
    local_addr.sin6_port = htons(base_port++); // Get a new port
#endif
    if (::bind(sockfd, reinterpret_cast<struct sockaddr *>(&local_addr),
               sizeof(local_addr)) == -1) {
      if (errno == EADDRINUSE) {
        ::close(sockfd);
        continue;
      }
      std::stringstream ss;
      ss << "Unable to bind socket: " << strerror(errno);
      ::close(sockfd);
      throw TestException{ss.str()};
    }
    if (num_ports == 0U) {
      /* Set socket timeout */
      if (::setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const void *>(&timeout_),
                       sizeof(timeout_))) {
        ::close(sockfd);
        throw TestException("Cannot set timeout: setsockopt failed");
      }
    } else {
      /* Set socket nonblocking */
      int flags = fcntl(sockfd, F_GETFL);
      if (flags < 0) {
        std::stringstream ss;
        ss << "F_GETFL failed: " << strerror(errno);
        ::close(sockfd);
        throw TestException{ss.str()};
      }
      if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        std::stringstream ss;
        ss << "F_SETFL failed: " << strerror(errno);
        ::close(sockfd);
        throw TestException{ss.str()};
      }
    }
    /* Try to enable SO_TXTIME for precise rate limiting */
    struct sock_txtime txtime_cfg;
    txtime_cfg.clockid = CLOCK_TAI;
    txtime_cfg.flags = 0;
    if (::setsockopt(sockfd, SOL_SOCKET, SO_TXTIME, &txtime_cfg,
                     sizeof(txtime_cfg)) < 0) {
      std::cerr << "Warning: SO_TXTIME not available (kernel may not support "
                    "it). Falling back to spin_sleep. Error: "
                 << strerror(errno) << std::endl;
      use_so_txtime_ = false;
    }
    sockets_.emplace_back(sockfd);
  }
  if (num_ports > 0U) {
    /* Fill pollfds */
    pollfds_.resize(num_ports);
    for (size_t i = 0; i < num_ports; i++) {
      pollfds_[i].fd = sockets_[i];
      pollfds_[i].events = POLLIN;
      pollfds_[i].revents = 0;
    }
  }
  /* Preallocate the test queries */
  tests_.reserve(num_req_);
  /* Create the test queries */
  for (uint32_t i = 0; i < num_req_; i++) {
    tests_.push_back(DnsQuery{
        static_cast<uint16_t>(i % (num_ports == 0U ? 1U : num_ports))});
  }
}

void DnsTester::test() {
  /* Get reference TAI time once at the start - required for SO_TXTIME batching */
  uint64_t start_tai_ns = get_clock_tai_ns();

  uint32_t packets_in_batch = 0;
  uint64_t txtime_ns = start_tai_ns;  /* Track the txtime of the next packet to send */

  /* Send all packets with SO_TXTIME scheduling */
  while (num_sent_ < num_req_) {
    /* Get query store */
    DnsQuery &query = tests_[num_sent_];

    /* Select the entry from the local list (cycling with modulo) */
    const QueryFileEntry &entry =
        queries_[(query_start_ + num_sent_) % queries_.size()];

    /* Copy pre-serialized packet into the send buffer */
    size_t pkt_len = entry.packet.size();
    memcpy(query_data_, entry.packet.data(), pkt_len);

    /* Patch the TX ID in-place (use modulo to handle TX ID space reuse) */
    uint16_t tx_id = static_cast<uint16_t>(num_sent_ % 65536);
    reinterpret_cast<DNSHeader *>(query_data_)->id(tx_id);

    /* Send the query */
    ssize_t sent = -1;
    /* Use SO_TXTIME for scheduling */
    while ((sent = sendto_with_txtime(
                sockets_[query.socket_index_],
                reinterpret_cast<const void *>(query_data_), pkt_len, 0,
                reinterpret_cast<const struct sockaddr *>(&server_),
                sizeof(server_), txtime_ns)) != static_cast<ssize_t>(pkt_len)) {
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        std::cerr << "Can't send packet with SO_TXTIME." << std::endl;
        break;
      }
    }

    /* Store the time */
    query.time_sent_ = std::chrono::time_point<std::chrono::high_resolution_clock>(
        std::chrono::nanoseconds(txtime_ns));
    m_.lock();
    tx_to_query_[tx_id] = num_sent_;
    num_sent_++;
    m_.unlock();

    /* Increment batch counter and sleep after batch_size queries */
    packets_in_batch++;
    if (packets_in_batch >= batch_size_ && num_sent_ < num_req_) {
      uint64_t current_tai_ns = get_clock_tai_ns();
      uint64_t sleep_target_ns = txtime_ns - interval_ns_.count(); /*Wake up 1 query prior to the last send time*/
      if (sleep_target_ns > current_tai_ns) {
        uint64_t sleep_duration_ns = sleep_target_ns - current_tai_ns;
        if (sleep_duration_ns >= min_sleep_ns_) {
          struct timespec ts;
          ts.tv_sec = sleep_duration_ns / 1000000000ULL;
          ts.tv_nsec = sleep_duration_ns % 1000000000ULL;
          nanosleep(&ts, nullptr);
        } else {
          spinsleep::sleep_for(std::chrono::nanoseconds(sleep_duration_ns));
        }
      }
      packets_in_batch = 0;
    }
    txtime_ns += interval_ns_.count();  /* Increment Running count for next query */
  }
}

inline void DnsTester::receive(uint16_t socket_index) {
#ifdef DNS64PERFPP_IPV4
  struct sockaddr_in sender;
#else
  struct sockaddr_in6 sender;
#endif
  socklen_t sender_len;
  ssize_t recvlen;
  memset(&sender, 0x00, sizeof(sender));
  sender_len = sizeof(sender);
  if ((recvlen = ::recvfrom(
           sockets_[socket_index], answer_data_.data(), answer_data_.size(), 0,
           reinterpret_cast<struct sockaddr *>(&sender), &sender_len)) > 0) {
    /* Get the time of the receipt (using CLOCK_TAI for consistency with SO_TXTIME) */
    uint64_t time_received_ns = get_clock_tai_ns();
    std::chrono::high_resolution_clock::time_point time_received =
        std::chrono::high_resolution_clock::time_point(std::chrono::nanoseconds(time_received_ns));
/* Test whether the answer came from the DUT */
#ifdef DNS64PERFPP_IPV4
    if (memcmp(reinterpret_cast<const void *>(&sender.sin_addr),
               reinterpret_cast<const void *>(&server_.sin_addr),
               sizeof(struct in_addr)) != 0 ||
        sender.sin_port != server_.sin_port) {
      char sender_text[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, reinterpret_cast<const void *>(&sender.sin_addr),
                sender_text, sizeof(sender_text));
      std::stringstream ss;
      ss << "Received packet from other host than the DUT: " << sender_text
         << ":" << ntohs(sender.sin_port);
      throw TestException{ss.str()};
#else
    if (memcmp(reinterpret_cast<const void *>(&sender.sin6_addr),
               reinterpret_cast<const void *>(&server_.sin6_addr),
               sizeof(struct in6_addr)) != 0 ||
        sender.sin6_port != server_.sin6_port) {
      char sender_text[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, reinterpret_cast<const void *>(&sender.sin6_addr),
                sender_text, sizeof(sender_text));
      std::stringstream ss;
      ss << "Received packet from other host than the DUT: [" << sender_text
         << "]:" << ntohs(sender.sin6_port);
      throw TestException{ss.str()};
#endif
    }
    /* Parse the answer */
    DNSPacket answer{answer_data_.data(), (size_t)recvlen, answer_data_.size()};
    /* Test whether the query is valid */
    if (answer.header_->qdcount() < 1) {
      /* It is invalid */
      return;
    }
    /* Find the corresponding query using TX ID */
    uint16_t tx_id = answer.header_->id();
    m_.lock();
    uint32_t query_idx = tx_to_query_[tx_id];
    if (query_idx == UINT32_MAX) {
      /* TX ID not found in pending queries — discard (stale or misrouted) */
      m_.unlock();
      return;
    }
    tx_to_query_[tx_id] = UINT32_MAX;
    m_.unlock();

    DnsQuery &query = tests_[query_idx];
    /* Set the received flag true */
    query.received_ = true;
    /* Set the received timestamp */
    query.time_received_ = time_received;
    /* Check whether there is an answer */
    query.answered_ = answer.header_->qr() == 1 &&
                      answer.header_->rcode() == DNSHeader::RCODE::NoError &&
                      answer.header_->ancount() > 0;
  } else {
    /* If the error is not caused by timeout, there is something wrong */
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      std::stringstream ss;
      ss << "Error in recvfrom: " << strerror(errno);
      throw TestException{ss.str()};
    }
  }
}

void DnsTester::start() {
  /* Wait until test_start_time, then send all packets with SO_TXTIME scheduling */
  spinsleep::sleep_until(test_start_time_);
  this->test();

  /* Receiving answers */
  bool continue_receiving;
  std::chrono::time_point<std::chrono::high_resolution_clock> receive_until;

  continue_receiving = true;
  while (continue_receiving ||
         std::chrono::high_resolution_clock::now() <= receive_until) {
    m_.lock();
    size_t remaining = num_req_ - num_sent_;
    m_.unlock();
    if (continue_receiving && remaining == 0) {
      continue_receiving = false;
      receive_until = std::chrono::high_resolution_clock::now() +
                      std::chrono::seconds{timeout_.tv_sec} +
                      std::chrono::microseconds{timeout_.tv_usec};
    }
    if (pollfds_.size() > 0U) {
      int ret = ::poll(pollfds_.data(), static_cast<nfds_t>(pollfds_.size()),
                       200 /*ms*/);
      if (ret < 0) {
        std::stringstream ss;
        ss << "Error on poll() " << strerror(errno);
        throw TestException{ss.str()};
      }
      if (ret == 0) {
        /* Timeout */
        continue;
      }
      for (size_t i = 0; i < pollfds_.size(); i++) {
        if (pollfds_[i].revents == 0) {
          continue;
        }
        if (pollfds_[i].revents != POLLIN) {
          std::stringstream ss;
          ss << "Error on socket, revents: " << pollfds_[i].revents;
          throw TestException{ss.str()};
        }
        this->receive(i);
      }
    } else {
      this->receive(0U);
    }
  }

  for (auto &query : tests_) {
    /* Calculate the Round-Trip-Time */
    if (query.received_) {
      query.rtt_ = std::chrono::duration_cast<std::chrono::nanoseconds>(
          query.time_received_ - query.time_sent_);
    }
    /* Adjust answer validity with timeout */
    query.answered_ =
        query.answered_ &&
        query.rtt_ < (std::chrono::seconds{timeout_.tv_sec} +
                      std::chrono::microseconds{timeout_.tv_usec});
  }
}

DnsTesterAggregator::DnsTesterAggregator(
    const std::vector<std::unique_ptr<DnsTester>> &dns_testers)
    : dns_testers_(dns_testers) {}

void DnsTesterAggregator::display() {
  uint32_t num_received, num_answered, num_total;
  double average, standard_deviation;
  num_total = 0;
  num_received = 0;
  num_answered = 0;
  /* Number of received and answered queries */
  for (const auto &tester : dns_testers_) {
    for (const auto &query : tester->tests_) {
      num_total++;
      if (query.received_) {
        num_received++;
      }
      if (query.answered_) {
        num_answered++;
      }
    }
  }
  /* Average */
  average = 0;
  for (const auto &tester : dns_testers_) {
    for (const auto &query : tester->tests_) {
      if (query.received_) {
        average += (double)query.rtt_.count() / num_received;
      }
    }
  }
  /* Standard deviation */
  standard_deviation = 0;
  for (const auto &tester : dns_testers_) {
    for (auto &query : tester->tests_) {
      if (query.received_) {
        standard_deviation += pow(query.rtt_.count() - average, 2.0);
      }
    }
  }
  standard_deviation = sqrt(standard_deviation / num_received);
  /* Print results */
  printf("Sent queries: %u\n", num_total);
  printf("Received answers: %u (%.02f%%)\n", num_received,
         ((double)num_received / num_total) * 100);
  printf("Valid answers: %u (%.02f%%)\n", num_answered,
         ((double)num_answered / num_total) * 100);
  printf("Average round-trip time: %.02f ms\n", average / 1000000.0);
  printf("Standard deviation of the round-trip time: %.02f ms\n",
         standard_deviation / 1000000.0);
}

void DnsTesterAggregator::write(const char *filename) {
  const auto &first_tester = dns_testers_[0];
/* Convert server address to string */
#ifdef DNS64PERFPP_IPV4
  char server[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET,
                reinterpret_cast<const void *>(&first_tester->server_.sin_addr),
                server, sizeof(server)) == NULL) {
#else
  char server[INET6_ADDRSTRLEN];
  if (inet_ntop(
          AF_INET6,
          reinterpret_cast<const void *>(&first_tester->server_.sin6_addr),
          server, sizeof(server)) == NULL) {
#endif
    std::stringstream ss;
    ss << "Bad server address: " << strerror(errno);
    throw TestException{ss.str()};
  }
  /* Open file */
  FILE *fp;
  if ((fp = fopen(filename, "w")) == nullptr) {
    throw TestException{"Can't open file"};
  }
  /* Write header */
  fprintf(fp, "%s\n", "dns64perf++ test parameters");
  fprintf(fp, "server: %s\n", server);
#ifdef DNS64PERFPP_IPV4
  fprintf(fp, "port: %hu\n", ntohs(first_tester->server_.sin_port));
#else
  fprintf(fp, "port: %hu\n", ntohs(first_tester->server_.sin6_port));
#endif
  fprintf(fp, "number of requests: %u\n",
          first_tester->num_req_ * first_tester->num_thread_);
  fprintf(fp, "number of threads: %u\n", first_tester->num_thread_);
  uint64_t qps = 1000000000ULL / first_tester->interval_ns_.count();
  fprintf(fp, "QPS (queries per second): %lu\n", qps);
  fprintf(fp, "per-packet interval: %lu ns\n\n",
          first_tester->interval_ns_.count());
  fprintf(
      fp,
      "query name;query type;thread id;tsent [ns];treceived [ns];received;answered;rtt [ns]\n");
  /* Write queries */
  for (const auto &tester : dns_testers_) {
    uint32_t n = 0;
    for (const auto &query : tester->tests_) {
      size_t file_idx = (tester->query_start_ + n) % tester->queries_.size();
      const QueryFileEntry &entry = tester->queries_[file_idx];
      auto it = QTypeStr.find(entry.qtype);
      const char *typestr = (it != QTypeStr.end()) ? it->second : "UNKNOWN";
      fprintf(fp, "%s;%s;%u;%lu;%lu;%d;%d;%ld\n", entry.name.c_str(), typestr,
              tester->thread_id_,
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  query.time_sent_.time_since_epoch())
                  .count(),
              std::chrono::duration_cast<std::chrono::nanoseconds>(
                  query.time_received_.time_since_epoch())
                  .count(),
              query.received_, query.answered_, query.rtt_.count());
      ++n;
    }
  }
  fclose(fp);
}
