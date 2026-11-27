add_library(twolink_handshake src/payload.cpp src/sas.cpp)
add_library(twolink::handshake ALIAS twolink_handshake)
target_include_directories(twolink_handshake PUBLIC include)
target_link_libraries(twolink_handshake
  PUBLIC twolink::core twolink::framing twolink::crypto
  PRIVATE unofficial-sodium::sodium twolink::options)
