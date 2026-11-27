add_library(twolink_session src/session.cpp)
add_library(twolink::session ALIAS twolink_session)
target_include_directories(twolink_session PUBLIC include)
target_link_libraries(twolink_session
  PUBLIC twolink::core twolink::framing twolink::crypto
  PRIVATE unofficial-sodium::sodium twolink::options)
