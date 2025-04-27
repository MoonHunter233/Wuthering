#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct FirewallRule {
  std::string srcIp;
  std::string dstIp;
  uint16_t srcPort;
  uint16_t dstPort;
  std::string protocol; // "TCP", "UDP", "ANY"
  enum Action { ALLOW, DENY } action;
};

class Firewall {
public:
  bool loadRules(const std::string &path);
  bool allow(const std::vector<uint8_t> &packet);

private:
  std::vector<FirewallRule> rules_;
  bool match(const FirewallRule &rule, const std::vector<uint8_t> &packet);
};
