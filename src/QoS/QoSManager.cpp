#include "QoS/QoSManager.h"
#include <arpa/inet.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sstream>

static bool ipMatch(const std::string &ruleIp, uint32_t actual) {
  if (ruleIp == "ANY")
    return true;
  in_addr ruleAddr;
  inet_aton(ruleIp.c_str(), &ruleAddr);
  return ruleAddr.s_addr == actual;
}

bool QoSManager::loadRules(const std::string &path) {
  std::ifstream in(path);
  if (!in)
    return false;

  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#')
      continue;

    std::istringstream ss(line);
    QoSRule rule;
    std::string rateStr;

    ss >> rule.srcIp >> rule.dstIp >> rule.protocol >> rateStr;
    rule.maxRateBytesPerSec = std::stoull(rateStr);

    rules_.push_back(rule);
  }

  std::cout << "[QoS] Loaded " << rules_.size() << " QoS rules.\n";
  return true;
}

bool QoSManager::match(const QoSRule &rule,
                       const std::vector<uint8_t> &packet) {
  const iphdr *ip = reinterpret_cast<const iphdr *>(packet.data());

  if (!ipMatch(rule.srcIp, ip->saddr))
    return false;
  if (!ipMatch(rule.dstIp, ip->daddr))
    return false;

  uint8_t protocol = ip->protocol;
  if (rule.protocol != "ANY") {
    if ((rule.protocol == "TCP" && protocol != IPPROTO_TCP) ||
        (rule.protocol == "UDP" && protocol != IPPROTO_UDP)) {
      return false;
    }
  }

  return true;
}

uint64_t QoSManager::nowMs() {
  auto now = std::chrono::steady_clock::now();
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             now.time_since_epoch())
      .count();
}

bool QoSManager::allow(const std::vector<uint8_t> &packet) {
  for (const auto &rule : rules_) {
    if (match(rule, packet)) {
      std::string flowKey = rule.srcIp + "_" + rule.dstIp + "_" + rule.protocol;
      auto &state = flowTable_[flowKey];

      uint64_t current = nowMs();
      uint64_t elapsed = current - state.lastCheckTimeMs;
      if (elapsed > 1000) { // 每秒刷新
        state.bytesSent = 0;
        state.lastCheckTimeMs = current;
      }

      if (state.bytesSent + packet.size() > rule.maxRateBytesPerSec) {
        return false; // 超速，丢弃
      }

      state.bytesSent += packet.size();
      return true;
    }
  }

  return true; // 没有匹配规则，默认放行
}
