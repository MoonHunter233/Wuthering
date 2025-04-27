#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

class NATManager {
public:
  void setPublicIp(const std::string &ip);
  std::vector<uint8_t> applySNAT(const std::vector<uint8_t> &packet);

private:
  std::string publicIp_;
};
