cmake_minimum_required(VERSION 3.2.0)

add_library(COMPONMENT_RAWMEMFILE rawmem2dma.cpp)

target_link_libraries(COMPONMENT_RAWMEMFILE COMPONMENT_DMA)
set_target_properties(
    COMPONMENT_RAWMEMFILE
    PROPERTIES
    CXX_STANDARD 17
    )
