cmake_minimum_required(VERSION 3.2.0)

#set(Boost_USE_STATIC_LIBS        ON)  # only find static libs
#set(Boost_USE_DEBUG_LIBS         OFF) # ignore debug libs and 
#set(Boost_USE_RELEASE_LIBS       ON)  # only find release libs 
#set(Boost_USE_MULTITHREADED      ON)
#set(Boost_USE_STATIC_RUNTIME    OFF) 
find_package(Boost COMPONENTS regex)

if(Boost_FOUND) 
    add_library(COMPONMENT_QEMUKVM qemukvm2dma.cpp)

    target_link_libraries(COMPONMENT_QEMUKVM fmt ${Boost_LIBRARIES} COMPONMENT_DMA)

    set_target_properties(
        COMPONMENT_QEMUKVM
        PROPERTIES
        CXX_STANDARD 17
        )
endif()
