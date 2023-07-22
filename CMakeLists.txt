cmake_minimum_required(VERSION 3.2.0)

# SET(CMAKE_C_COMPILER /usr/bin/clang)
# SET(CMAKE_CXX_COMPILER /usr/bin/clang++)
project(ceserver_rawmem VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -w -O3 -fdeclspec -fms-extensions")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w -O3 -fdeclspec -fms-extensions")

add_subdirectory(thirdparty/cpp-httplib)
add_subdirectory(thirdparty/cxxopts)
add_subdirectory(thirdparty/nlohmann_json)
add_subdirectory(thirdparty/raw_pdb)
add_subdirectory(thirdparty/spdlog)

add_subdirectory(dma)
add_subdirectory(dma_symbol)
add_subdirectory(tools)


add_executable(${PROJECT_NAME}
    main.cpp
    porthelp.c
    ceserver_interface.cpp
    ceserver_interface_impl.cpp
)

set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
    CXX_STANDARD 17
)

target_link_libraries(
    ${PROJECT_NAME}
    pthread
    dl
    z
    COMPONMENT_DMA
    COMPONMENT_PDB
)


add_subdirectory(rawmemfile)
target_link_libraries(${PROJECT_NAME} COMPONMENT_RAWMEMFILE)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_subdirectory(qemukvm)
    target_link_libraries(${PROJECT_NAME} COMPONMENT_QEMUKVM)
ENDIF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
