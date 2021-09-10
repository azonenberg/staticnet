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

	main.cpp
)

###############################################################################
#Linker settings
target_link_libraries(bridge
	m
	)

