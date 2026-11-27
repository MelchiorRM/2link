add_library(twolink_identity
  src/device_id.cpp)
add_library(twolink::identity ALIAS twolink_identity)
target_include_directories(twolink_identity PUBLIC include)
target_link_libraries(twolink_identity
  PUBLIC twolink::crypto
  PRIVATE unofficial-sodium::sodium twolink::options)
