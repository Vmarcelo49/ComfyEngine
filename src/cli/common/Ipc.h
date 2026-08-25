#pragma once

#include <string>

#include <nlohmann/json.hpp>

namespace cli {

std::string defaultSocketPath();

bool connectDaemon(const std::string &path, int &fdOut, std::string &errOut);
bool writeLine(int fd, const std::string &line);
bool readLine(int fd, std::string &lineOut);

} // namespace cli
