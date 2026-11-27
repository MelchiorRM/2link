add_library(twolink_identity
  src/device_id.cpp
  src/identity.cpp
  src/keystore_common.cpp)
if(WIN32)
  target_sources(twolink_identity PRIVATE src/keystore_windows.cpp)
  target_link_libraries(twolink_identity PRIVATE crypt32)
else()
  target_sources(twolink_identity PRIVATE src/keystore_posix.cpp)
endif()
add_library(twolink::identity ALIAS twolink_identity)
target_include_directories(twolink_identity PUBLIC include)
target_link_libraries(twolink_identity
  PUBLIC twolink::crypto
  PRIVATE unofficial-sodium::sodium twolink::options)
