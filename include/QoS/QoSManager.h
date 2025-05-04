#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

struct QoSRule {
  std::string srcIp;
  std::string dstIp;
  std::string protocol;
  uint64_t maxRateBytesPerSec;
};

class QoSManager {
public:
  bool loadRules(const std::string &path);
  bool allow(const std::vector<uint8_t> &packet);

private:
  struct FlowState {
    uint64_t bytesSent;
    uint64_t lastCheckTimeMs;
  };

  std::vector<QoSRule> rules_;
  std::unordered_map<std::string, FlowState> flowTable_;

  bool match(const QoSRule &rule, const std::vector<uint8_t> &packet);
  uint64_t nowMs();
};
