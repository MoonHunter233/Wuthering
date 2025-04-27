#include "firewall/Firewall.h"
#include <arpa/inet.h>
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

bool Firewall::loadRules(const std::string &path) {
  std::ifstream in(path);
  if (!in)
    return false;

  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#')
      continue;

    std::istringstream ss(line);
    FirewallRule rule;
    std::string srcPortStr, dstPortStr, actionStr;

    ss >> rule.srcIp >> rule.dstIp >> srcPortStr >> dstPortStr >>
        rule.protocol >> actionStr;

    rule.srcPort = static_cast<uint16_t>(std::stoi(srcPortStr));
    rule.dstPort = static_cast<uint16_t>(std::stoi(dstPortStr));
    rule.action =
        (actionStr == "ALLOW") ? FirewallRule::ALLOW : FirewallRule::DENY;

    rules_.push_back(rule);
  }

  std::cout << "[Firewall] Loaded " << rules_.size() << " rules.\n";
  return true;
}

bool Firewall::match(const FirewallRule &rule,
                     const std::vector<uint8_t> &packet) {
  const iphdr *ip = reinterpret_cast<const iphdr *>(packet.data());

  if (!ipMatch(rule.srcIp, ip->saddr))
    return false;
  if (!ipMatch(rule.dstIp, ip->daddr))
    return false;

  // Check protocol
  uint8_t protocol = ip->protocol;
  if (rule.protocol != "ANY") {
    if ((rule.protocol == "TCP" && protocol != IPPROTO_TCP) ||
        (rule.protocol == "UDP" && protocol != IPPROTO_UDP)) {
      return false;
    }
  }

  // Check ports if TCP/UDP
  if (protocol == IPPROTO_TCP &&
      packet.size() >= ip->ihl * 4 + sizeof(tcphdr)) {
    const tcphdr *tcp =
        reinterpret_cast<const tcphdr *>(packet.data() + ip->ihl * 4);
    if (rule.srcPort != 0 && ntohs(tcp->source) != rule.srcPort)
      return false;
    if (rule.dstPort != 0 && ntohs(tcp->dest) != rule.dstPort)
      return false;
  } else if (protocol == IPPROTO_UDP &&
             packet.size() >= ip->ihl * 4 + sizeof(udphdr)) {
    const udphdr *udp =
        reinterpret_cast<const udphdr *>(packet.data() + ip->ihl * 4);
    if (rule.srcPort != 0 && ntohs(udp->source) != rule.srcPort)
      return false;
    if (rule.dstPort != 0 && ntohs(udp->dest) != rule.dstPort)
      return false;
  }

  return true;
}

bool Firewall::allow(const std::vector<uint8_t> &packet) {
  for (const auto &rule : rules_) {
    if (match(rule, packet)) {
      return rule.action == FirewallRule::ALLOW;
    }
  }
  return true; // 默认允许
}
