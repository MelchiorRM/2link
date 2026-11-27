# Command logic as a library so tests can exercise it.
add_library(twolink_cli_lib src/args.cpp src/peers.cpp src/app.cpp)
add_library(twolink::cli_lib ALIAS twolink_cli_lib)
target_include_directories(twolink_cli_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(twolink_cli_lib
  PUBLIC twolink::identity
  PRIVATE twolink::core twolink::transport twolink::discovery twolink::handshake twolink::options)

add_executable(twolink_cli main.cpp)
set_target_properties(twolink_cli PROPERTIES OUTPUT_NAME 2link)
target_link_libraries(twolink_cli PRIVATE twolink::cli_lib twolink::options)
