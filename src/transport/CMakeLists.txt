add_library(twolink_transport src/link.cpp)
add_library(twolink::transport ALIAS twolink_transport)
target_include_directories(twolink_transport PUBLIC include)
target_link_libraries(twolink_transport
  PUBLIC twolink::connection twolink::identity asio::asio
  PRIVATE twolink::options)
target_compile_definitions(twolink_transport PUBLIC ASIO_NO_DEPRECATED)
if(WIN32)
  target_compile_definitions(twolink_transport PUBLIC _WIN32_WINNT=0x0A00)  # Windows 10
endif()
