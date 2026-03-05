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

#include "spin_sleep.hpp"
#include <ctime>

namespace spinsleep {
void sleep_until(
    const std::chrono::time_point<std::chrono::high_resolution_clock>
        &sleep_target) {
  while (std::chrono::high_resolution_clock::now() < sleep_target)
    ;
}

uint64_t calibrate_min_sleep() {
  struct timespec start, stop;
  struct timespec wait = {0, 0};

  if (clock_gettime(CLOCK_REALTIME, &start) < 0) {
    return 1000000;  // Default 1ms if measurement fails
  }

  // Call nanosleep 100 times with 0 sleep
  for (int i = 0; i < 100; i++) {
    nanosleep(&wait, NULL);
  }

  if (clock_gettime(CLOCK_REALTIME, &stop) < 0) {
    return 1000000;  // Default 1ms if measurement fails
  }

  // Calculate elapsed time
  uint64_t elapsed_ns = ((uint64_t)stop.tv_sec - (uint64_t)start.tv_sec) * 1000000000ULL +
                        ((uint64_t)stop.tv_nsec - (uint64_t)start.tv_nsec);

  // Average per nanosleep call, with 3x safety factor
  uint64_t min_sleep = (elapsed_ns / 100) * 3;

  return min_sleep;
}
} // namespace spinsleep
