add_library(twolink_core src/version.cpp)
add_library(twolink::core ALIAS twolink_core)
target_include_directories(twolink_core PUBLIC include)
target_link_libraries(twolink_core PRIVATE twolink::options)
target_compile_definitions(twolink_core PRIVATE
  TWOLINK_VERSION_STRING="${PROJECT_VERSION}")
