add_executable(twolink_cli main.cpp)
set_target_properties(twolink_cli PROPERTIES OUTPUT_NAME 2link)
target_link_libraries(twolink_cli PRIVATE twolink::core twolink::framing twolink::options)
