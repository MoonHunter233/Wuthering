#pragma once

#include <cstdint>
#include <optional>
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
  std::string getPublicIp();

  std::vector<uint8_t> applySNAT(const std::vector<uint8_t> &packet);
  std::vector<uint8_t> applyDNAT(const std::vector<uint8_t> &packet);

  // 用于 TcpRelay 获取源地址
  bool getOriginalSource(const std::string &relayKey, std::string &ip,
                         uint16_t &port);

private:
  std::string publicIp_;
  std::unordered_map<std::string, NATEntry> natTable_; // 外部 → 内部
  std::unordered_map<std::string, std::string> reverseTable_; // 内部 → 外部 key
  std::unordered_map<std::string, NATEntry>
      relayReverseTable_; // 外部 key → 原始 NATEntry

  uint16_t allocateExternalPort();
  std::string makeNatKey(const std::string &ip, uint16_t port,
                         uint8_t protocol);
  std::string makeReverseKey(const std::string &ip, uint16_t port,
                             uint8_t protocol);
};
