# CMake build script for staticnet
# Intended to be integrated into a larger project, not built standalone.

if(BUILD_APB_LIBS)
	set(APB_SOURCES
		drivers/apb/APBEthernetInterface.cpp)
else()
	set(APB_SOURCES
		)
endif()


add_library(staticnet STATIC
	cli/SSHOutputStream.cpp

	contrib/base64.cpp
	contrib/tweetnacl_25519.cpp

	crypt/CryptoEngine.cpp

	dhcp/DHCPClient.cpp
	dhcp/DHCPPacket.cpp

	${APB_SOURCES}

	drivers/base/EthernetInterface.cpp
	drivers/stm32/STM32CryptoEngine.cpp
	# todo: proper selection of others

	net/arp/ARPCache.cpp
	net/arp/ARPPacket.cpp
	net/arp/ARPProtocol.cpp

	net/ethernet/EthernetFrame.cpp
	net/ethernet/EthernetProtocol.cpp

	net/icmpv4/ICMPv4Protocol.cpp

	net/ipv4/IPv4Packet.cpp
	net/ipv4/IPv4Protocol.cpp

	net/tcp/TCPProtocol.cpp
	net/tcp/TCPSegment.cpp

	net/udp/UDPPacket.cpp
	net/udp/UDPProtocol.cpp

	ntp/NTPClient.cpp

	sftp/SFTPServer.cpp

	ssh/SSHCurve25519KeyBlob.cpp
	ssh/SSHCurve25519SignatureBlob.cpp
	ssh/SSHKexEcdhReplyPacket.cpp
	ssh/SSHKexInitPacket.cpp
	ssh/SSHTransportPacket.cpp
	ssh/SSHTransportServer.cpp
	)

target_include_directories(staticnet
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
	"$<TARGET_PROPERTY:stm32-cpp,INTERFACE_INCLUDE_DIRECTORIES>"
	)
