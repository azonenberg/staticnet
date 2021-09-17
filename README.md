# Static Network Stack

TCP/IP stack with all-static allocations designed for bare metal (no operating system) embedded applications with
minimal footprint.

staticnet is intended to comply with a strict subset of the relevant RFCs. In the interest of simplicity and security,
many infrequently used features such as IP fragmentation are not supported.

staticnet is written in bare bones C++ with no runtime library dependencies other than memcpy(), memset(), and
memmove(). It uses a zero copy API rather than the conventional BSD sockets API to minimize unnecessary data shuffling.
