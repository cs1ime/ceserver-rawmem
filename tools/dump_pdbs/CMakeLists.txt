cmake_minimum_required(VERSION 3.0.0)

project(dump_pdbs)

add_executable(${PROJECT_NAME}
    dump_pdb.cpp
    ExampleMemoryMappedFile.cpp
    pdb_helper.cpp
    pdb_parser.cpp)

set_target_properties(${PROJECT_NAME}  PROPERTIES CXX_STANDARD 17)

target_link_libraries(
    ${PROJECT_NAME} 
    raw_pdb
)
