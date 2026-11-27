add_library(twolink_crypto src/keys.cpp src/noise.cpp)
add_library(twolink::crypto ALIAS twolink_crypto)
target_include_directories(twolink_crypto PUBLIC include)
target_link_libraries(twolink_crypto
  PUBLIC unofficial-sodium::sodium
  PRIVATE twolink::noisec twolink::options)
