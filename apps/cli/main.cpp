#include <iostream>

#include "twolink/core/version.hpp"

int main() {
  std::cout << "2link " << twolink::library_version()
            << " (protocol v" << static_cast<int>(twolink::kProtocolVersion) << ")\n";
  return 0;
}
