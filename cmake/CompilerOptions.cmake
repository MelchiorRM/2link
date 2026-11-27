add_library(twolink_options INTERFACE)
add_library(twolink::options ALIAS twolink_options)

if(MSVC)
  # Third-party headers (#include <...>, e.g. Asio) are not held to our warning level.
  target_compile_options(twolink_options INTERFACE /W4 /permissive- /external:anglebrackets
                                                   /external:W0)
  if(TWOLINK_WARNINGS_AS_ERRORS)
    target_compile_options(twolink_options INTERFACE /WX)
  endif()
else()
  target_compile_options(twolink_options INTERFACE
    -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow)
  if(TWOLINK_WARNINGS_AS_ERRORS)
    target_compile_options(twolink_options INTERFACE -Werror)
  endif()
  if(TWOLINK_SANITIZE)
    target_compile_options(twolink_options INTERFACE
      -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
    target_link_options(twolink_options INTERFACE -fsanitize=address,undefined)
  endif()
  if(TWOLINK_FUZZ)
    # Coverage instrumentation for libraries; fuzz targets add -fsanitize=fuzzer.
    target_compile_options(twolink_options INTERFACE -fsanitize=fuzzer-no-link)
  endif()
endif()
