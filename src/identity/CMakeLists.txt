add_library(twolink_identity
  src/device_id.cpp
  src/identity.cpp
  src/keystore_common.cpp
  src/trust_store.cpp)
if(WIN32)
  target_sources(twolink_identity PRIVATE src/keystore_windows.cpp src/private_file_windows.cpp)
  target_link_libraries(twolink_identity PRIVATE crypt32)
else()
  target_sources(twolink_identity PRIVATE src/keystore_posix.cpp src/private_file_posix.cpp)
endif()
add_library(twolink::identity ALIAS twolink_identity)
target_include_directories(twolink_identity PUBLIC include)
target_link_libraries(twolink_identity
  PUBLIC twolink::crypto
  PRIVATE twolink::core unofficial-sodium::sodium twolink::options)
