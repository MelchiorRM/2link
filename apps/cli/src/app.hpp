#pragma once

// The 2link CLI commands.

#include <iosfwd>
#include <string>
#include <string_view>

#include "args.hpp"

namespace twolink::cli {

// Runs a parsed command; returns the process exit code. Interactive commands
// read lines from standard input.
[[nodiscard]] int run(const Command& command, std::ostream& out, std::ostream& err);

// Text from the network made safe for a terminal: C0/C1 control characters
// and DEL become '?', so a peer cannot inject escape sequences (threat T5).
[[nodiscard]] std::string printable(std::string_view untrusted);

}  // namespace twolink::cli
