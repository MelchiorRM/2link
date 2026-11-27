add_library(twolink_connection src/pairing_gate.cpp src/payloads.cpp src/connection.cpp)
add_library(twolink::connection ALIAS twolink_connection)
target_include_directories(twolink_connection PUBLIC include)
target_link_libraries(twolink_connection
  PUBLIC twolink::core twolink::framing twolink::crypto twolink::identity twolink::session
         twolink::handshake
  PRIVATE unofficial-sodium::sodium twolink::options)
