include_directories(../../)
include_directories(.)

###############################################################################
#C++ compilation
add_executable(bridge
	../../drivers/base/EthernetInterface.cpp
	../../drivers/tap/TapEthernetInterface.cpp

	../../net/arp/ARPCache.cpp
	../../net/arp/ARPPacket.cpp
	../../net/arp/ARPProtocol.cpp
	../../net/ethernet/EthernetFrame.cpp
	../../net/ethernet/EthernetProtocol.cpp
	../../net/icmpv4/ICMPv4Protocol.cpp
	../../net/ipv4/IPv4Packet.cpp
	../../net/ipv4/IPv4Protocol.cpp
	../../net/tcp/TCPSegment.cpp
	../../net/tcp/TCPProtocol.cpp

	../../ssh/SSHTransportServer.cpp

	main.cpp
	BridgeTCPProtocol.cpp
)

###############################################################################
#Linker settings
target_link_libraries(bridge
	m
	)

