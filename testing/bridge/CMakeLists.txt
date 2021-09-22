include_directories(../../)
include_directories(.)

###############################################################################
#C++ compilation
add_executable(bridge
	../../crypt/CryptoEngine.cpp

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

	../../ssh/SSHKexEcdhReplyPacket.cpp
	../../ssh/SSHKexInitPacket.cpp
	../../ssh/SSHTransportPacket.cpp
	../../ssh/SSHTransportServer.cpp

	../../contrib/tweetnacl_25519.cpp

	main.cpp
	BridgeCryptoEngine.cpp
	BridgeSSHTransportServer.cpp
	BridgeTCPProtocol.cpp
)

###############################################################################
#Linker settings
target_link_libraries(bridge
	m
	)

