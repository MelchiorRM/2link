add_library(twolink_framing src/frame.cpp src/frame_parser.cpp)
add_library(twolink::framing ALIAS twolink_framing)
target_include_directories(twolink_framing PUBLIC include)
target_link_libraries(twolink_framing PUBLIC twolink::core PRIVATE twolink::options)
