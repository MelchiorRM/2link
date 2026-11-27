// 2link command-line front end (spec v0.1.3, Phase 1).

#include <iostream>
#include <string_view>
#include <variant>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include "src/app.hpp"
#include "src/args.hpp"

int main(int argc, char** argv) {
#ifdef _WIN32
  SetConsoleOutputCP(CP_UTF8);  // names and messages are UTF-8 (spec §1)
  SetConsoleCP(CP_UTF8);
#endif
  std::vector<std::string_view> args(argv + 1, argv + argc);
  const auto parsed = twolink::cli::parse_args(args);
  if (const auto* error = std::get_if<std::string>(&parsed)) {
    std::cerr << "2link: " << *error << "\n\n" << twolink::cli::usage();
    return 2;
  }
  const int code = twolink::cli::run(std::get<twolink::cli::Command>(parsed), std::cout, std::cerr);
  std::cout.flush();
  return code;
}
