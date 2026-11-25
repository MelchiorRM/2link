// Runs a fuzz target over files given on the command line, for compilers
// without libFuzzer (GCC, MSVC). Used to replay crashes and corpus files.

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    std::ifstream in(argv[i], std::ios::binary);
    if (!in) {
      std::cerr << "cannot open " << argv[i] << '\n';
      return 1;
    }
    const std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(in),
                                          std::istreambuf_iterator<char>()};
    LLVMFuzzerTestOneInput(bytes.data(), bytes.size());
    std::cout << "ok " << argv[i] << '\n';
  }
  return 0;
}
