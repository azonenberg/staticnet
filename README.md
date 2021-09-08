# Static Network Stack

TCP/IP stack with all-static allocations designed for bare metal (no operating system) embedded applications with
minimal footprint.

staticnet is written in bare bones C++ with no runtime library dependencies other than memcpy() and uses a zero copy
API rather than the conventional BSD sockets API to minimize unnecessary data shuffling.
