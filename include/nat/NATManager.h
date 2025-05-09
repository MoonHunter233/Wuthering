#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

struct NATEntry {
  std::string internalIp;
  uint16_t internalPort;
  std::string externalIp;
  uint16_t externalPort;
  uint8_t protocol;
};

class NATManager {
public:
  void setPublicIp(const std::string &ip);

  std::vector<uint8_t> applySNAT(const std::vector<uint8_t> &packet);
  std::vector<uint8_t> applyDNAT(const std::vector<uint8_t> &packet);

private:
  std::string publicIp_;
  std::unordered_map<std::string, NATEntry> natTable_;

  uint16_t allocateExternalPort();
  std::string makeNatKey(const std::string &ip, uint16_t port,
                         uint8_t protocol);
};
