add_library(twolink_discovery src/announcement.cpp src/device_table.cpp)
add_library(twolink::discovery ALIAS twolink_discovery)
target_include_directories(twolink_discovery PUBLIC include)
target_link_libraries(twolink_discovery
  PUBLIC twolink::core twolink::identity asio::asio
  PRIVATE twolink::options)
target_compile_definitions(twolink_discovery PUBLIC ASIO_NO_DEPRECATED)
if(WIN32)
  target_compile_definitions(twolink_discovery PUBLIC _WIN32_WINNT=0x0A00)
endif()
