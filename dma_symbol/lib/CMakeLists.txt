add_library(COMPONMENT_PDB
downloader.cpp
dma_symbol_impl.cpp
ExampleMemoryMappedFile.cpp
pdb_helper.cpp
pdb_parser.cpp
)

target_include_directories(COMPONMENT_PDB PRIVATE ../include)
target_include_directories(COMPONMENT_PDB PRIVATE ../../dma/include)

set_target_properties(
    COMPONMENT_PDB
    PROPERTIES
    CXX_STANDARD 17
    
    )
find_package(OpenSSL 1.1.1 REQUIRED)
target_link_libraries(
    COMPONMENT_PDB
    raw_pdb
    spdlog
    cxxopts
    nlohmann_json
    httplib
    OpenSSL::SSL
    OpenSSL::Crypto
)
