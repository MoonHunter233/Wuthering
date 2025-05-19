#include "nat/NATManager.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

static uint16_t ipChecksum(void *vdata, size_t length);

void NATManager::setPublicIp(const std::string &ip) { publicIp_ = ip; }

std::string NATManager::getPublicIp() { return publicIp_; }

uint16_t NATManager::allocateExternalPort() {
  static uint16_t port = 40000;
  return port++;
}

std::string NATManager::makeNatKey(const std::string &ip, uint16_t port,
                                   uint8_t protocol) {
  return ip + ":" + std::to_string(port) + ":" + std::to_string(protocol);
}

std::string NATManager::makeReverseKey(const std::string &ip, uint16_t port,
                                       uint8_t protocol) {
  return ip + ":" + std::to_string(port) + ":" + std::to_string(protocol);
}

std::vector<uint8_t> NATManager::applySNAT(const std::vector<uint8_t> &packet) {
  std::vector<uint8_t> modified = packet;
  iphdr *ip = reinterpret_cast<iphdr *>(modified.data());
  uint8_t proto = ip->protocol;
  uint16_t srcPort = 0;

  if (proto == IPPROTO_TCP && modified.size() >= ip->ihl * 4 + sizeof(tcphdr)) {
    auto *tcp = reinterpret_cast<tcphdr *>(modified.data() + ip->ihl * 4);
    srcPort = ntohs(tcp->source);
  } else if (proto == IPPROTO_UDP &&
             modified.size() >= ip->ihl * 4 + sizeof(udphdr)) {
    auto *udp = reinterpret_cast<udphdr *>(modified.data() + ip->ihl * 4);
    srcPort = ntohs(udp->source);
  }

  std::string srcIp = inet_ntoa(*(in_addr *)&ip->saddr);
  std::string reverseKey = makeReverseKey(srcIp, srcPort, proto);

  if (reverseTable_.count(reverseKey)) {
    const NATEntry &entry = natTable_[reverseTable_[reverseKey]];

    inet_aton(entry.externalIp.c_str(), (in_addr *)&ip->saddr);
    if (proto == IPPROTO_TCP) {
      auto *tcp = reinterpret_cast<tcphdr *>(modified.data() + ip->ihl * 4);
      tcp->source = htons(entry.externalPort);
    } else if (proto == IPPROTO_UDP) {
      auto *udp = reinterpret_cast<udphdr *>(modified.data() + ip->ihl * 4);
      udp->source = htons(entry.externalPort);
    }

    ip->check = 0;
    ip->check = ipChecksum(ip, ip->ihl * 4);
    return modified;
  }

  uint16_t extPort = allocateExternalPort();
  std::string natKey = makeNatKey(publicIp_, extPort, proto);
  NATEntry entry{srcIp, srcPort, publicIp_, extPort, proto};
  natTable_[natKey] = entry;
  reverseTable_[reverseKey] = natKey;

  inet_aton(publicIp_.c_str(), (in_addr *)&ip->saddr);
  if (proto == IPPROTO_TCP) {
    auto *tcp = reinterpret_cast<tcphdr *>(modified.data() + ip->ihl * 4);
    tcp->source = htons(extPort);
  } else if (proto == IPPROTO_UDP) {
    auto *udp = reinterpret_cast<udphdr *>(modified.data() + ip->ihl * 4);
    udp->source = htons(extPort);
  }

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
    auto *tcp = reinterpret_cast<tcphdr *>(modified.data() + ip->ihl * 4);
    dstPort = ntohs(tcp->dest);
  } else if (proto == IPPROTO_UDP &&
             modified.size() >= ip->ihl * 4 + sizeof(udphdr)) {
    auto *udp = reinterpret_cast<udphdr *>(modified.data() + ip->ihl * 4);
    dstPort = ntohs(udp->dest);
  }

  std::string dstIp = inet_ntoa(*(in_addr *)&ip->daddr);
  std::string key = makeNatKey(dstIp, dstPort, proto);

  auto it = natTable_.find(key);
  if (it == natTable_.end())
    return packet;

  const NATEntry &entry = it->second;
  inet_aton(entry.internalIp.c_str(), (in_addr *)&ip->daddr);

  if (proto == IPPROTO_TCP) {
    auto *tcp = reinterpret_cast<tcphdr *>(modified.data() + ip->ihl * 4);
    tcp->dest = htons(entry.internalPort);
  } else if (proto == IPPROTO_UDP) {
    auto *udp = reinterpret_cast<udphdr *>(modified.data() + ip->ihl * 4);
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

  while (acc >> 16)
    acc = (acc & 0xffff) + (acc >> 16);

  return htons(~acc);
}
