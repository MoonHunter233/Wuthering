#include "nat/NATManager.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

static uint16_t ipChecksum(void *vdata, size_t length);

void NATManager::setPublicIp(const std::string &ip) { publicIp_ = ip; }

uint16_t NATManager::allocateExternalPort() {
  static uint16_t port = 40000;
  return port++;
}

std::string NATManager::makeNatKey(const std::string &ip, uint16_t port,
                                   uint8_t protocol) {
  return ip + ":" + std::to_string(port) + ":" + std::to_string(protocol);
}

std::vector<uint8_t> NATManager::applySNAT(const std::vector<uint8_t> &packet) {
  const struct iphdr *iph =
      reinterpret_cast<const struct iphdr *>(packet.data());
  in_addr sr;
  sr.s_addr = iph->saddr;
  std::cout << "test:" << std::string(inet_ntoa(sr)) << "\n";

  std::vector<uint8_t> modified = packet;
  iphdr *ip = reinterpret_cast<iphdr *>(modified.data());

  uint8_t proto = ip->protocol;
  uint16_t srcPort = 0;

  if (proto == IPPROTO_TCP && modified.size() >= ip->ihl * 4 + sizeof(tcphdr)) {
    tcphdr *tcp = reinterpret_cast<tcphdr *>(modified.data() + ip->ihl * 4);
    srcPort = ntohs(tcp->source);
  } else if (proto == IPPROTO_UDP &&
             modified.size() >= ip->ihl * 4 + sizeof(udphdr)) {
    udphdr *udp = reinterpret_cast<udphdr *>(modified.data() + ip->ihl * 4);
    srcPort = ntohs(udp->source);
  }

  in_addr src;
  src.s_addr = ip->saddr;
  std::string srcIp = inet_ntoa(src);

  std::cout << "[SNAT] Original src:" << srcIp << ":" << srcPort
            << ",protocol:" << (int)proto << "\n";

  uint16_t externalPort = allocateExternalPort();
  natTable_[makeNatKey(publicIp_, externalPort, proto)] =
      NATEntry{srcIp, srcPort, publicIp_, externalPort, proto};

  // 替换 IP
  in_addr newAddr;
  inet_aton(publicIp_.c_str(), &newAddr);
  ip->saddr = newAddr.s_addr;

  // 替换端口
  if (proto == IPPROTO_TCP) {
    tcphdr *tcp = reinterpret_cast<tcphdr *>(modified.data() + ip->ihl * 4);
    tcp->source = htons(externalPort);
  } else if (proto == IPPROTO_UDP) {
    udphdr *udp = reinterpret_cast<udphdr *>(modified.data() + ip->ihl * 4);
    udp->source = htons(externalPort);
  }

  std::cout << "[SNAT] Mapped to: " << publicIp_ << ":" << externalPort << "\n";

  ip->check = 0;
  ip->check = ipChecksum(ip, ip->ihl * 4);

  return modified;
}

std::vector<uint8_t> NATManager::applyDNAT(const std::vector<uint8_t> &packet) {
  std::vector<uint8_t> modified = packet;
  iphdr *ip = reinterpret_cast<iphdr *>(modified.data());

  uint8_t proto = ip->protocol;
  uint16_t dstPort = 0;

  if (proto == IPPROTO_TCP && modified.size() >= ip->ihl * 4 + sizeof(tcphdr)) {
    tcphdr *tcp = reinterpret_cast<tcphdr *>(modified.data() + ip->ihl * 4);
    dstPort = ntohs(tcp->dest);
  } else if (proto == IPPROTO_UDP &&
             modified.size() >= ip->ihl * 4 + sizeof(udphdr)) {
    udphdr *udp = reinterpret_cast<udphdr *>(modified.data() + ip->ihl * 4);
    dstPort = ntohs(udp->dest);
  }

  std::string dstIp = inet_ntoa(*(in_addr *)&ip->daddr);

  std::cout << "[DNAT] Received dst: " << dstIp << ":" << dstPort
            << ", protocol: " << (int)proto << "\n";

  auto it = natTable_.find(makeNatKey(dstIp, dstPort, proto));
  if (it == natTable_.end()) {
    std::cout << "[DNAT] No NAT mapping found for key "
              << makeNatKey(dstIp, dstPort, proto) << "\n";
    return packet; // 没找到映射，不处理
  }

  const NATEntry &entry = it->second;

  std::cout << "[DNAT] Matched mapping: " << entry.internalIp << ":"
            << entry.internalPort << "\n";

  // 还原 IP
  in_addr newAddr;
  inet_aton(entry.internalIp.c_str(), &newAddr);
  ip->daddr = newAddr.s_addr;

  // 还原端口
  if (proto == IPPROTO_TCP) {
    tcphdr *tcp = reinterpret_cast<tcphdr *>(modified.data() + ip->ihl * 4);
    tcp->dest = htons(entry.internalPort);
  } else if (proto == IPPROTO_UDP) {
    udphdr *udp = reinterpret_cast<udphdr *>(modified.data() + ip->ihl * 4);
    udp->dest = htons(entry.internalPort);
  }

  ip->check = 0;
  ip->check = ipChecksum(ip, ip->ihl * 4);

  return modified;
}

static uint16_t ipChecksum(void *vdata, size_t length) {
  char *data = reinterpret_cast<char *>(vdata);
  uint64_t acc = 0;

  for (size_t i = 0; i + 1 < length; i += 2) {
    uint16_t word;
    memcpy(&word, data + i, 2);
    acc += ntohs(word);
  }

  if (length & 1) {
    uint16_t word = 0;
    memcpy(&word, data + length - 1, 1);
    acc += ntohs(word);
  }

  while (acc >> 16) {
    acc = (acc & 0xffff) + (acc >> 16);
  }

  return htons(~acc);
}
