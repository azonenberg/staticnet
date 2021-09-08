include_directories(../../)
include_directories(.)

###############################################################################
#C++ compilation
add_executable(bridge
	../../net/ethernet/EthernetFrame.cpp

	main.cpp
)

###############################################################################
#Linker settings
target_link_libraries(bridge
	m
	)

