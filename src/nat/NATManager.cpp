#include "nat/NATManager.h"
#include <arpa/inet.h>
#include <cstring>
#include <ifaddrs.h>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

static uint16_t ipChecksum(void *vdata, size_t length);

void NATManager::setPublicIp(const std::string &iface) {
  struct ifaddrs *ifAddrStruct = nullptr;
  getifaddrs(&ifAddrStruct);
  for (struct ifaddrs *ifa = ifAddrStruct; ifa != nullptr;
       ifa = ifa->ifa_next) {
    if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
        iface == ifa->ifa_name) {
      void *addr = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
      char ipStr[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, addr, ipStr, INET_ADDRSTRLEN);
      freeifaddrs(ifAddrStruct);
      publicIp_ = std::string(ipStr);
      return;
    }
  }
  freeifaddrs(ifAddrStruct);
  publicIp_ = "127.0.0.1";
}

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
  std::string reverseKey = makeReverseKey(srcIp, srcPort, proto);

  std::cout << "[SNAT] Original src:" << srcIp << ":" << srcPort
            << ",protocol:" << (int)proto << "\n";

  // 如果已存在映射，直接复用
  if (reverseTable_.count(reverseKey)) {
    std::string existingNatKey = reverseTable_[reverseKey];
    const NATEntry &entry = natTable_[existingNatKey];

    in_addr newAddr;
    inet_aton(entry.externalIp.c_str(), &newAddr);
    ip->saddr = newAddr.s_addr;

    if (proto == IPPROTO_TCP) {
      tcphdr *tcp = reinterpret_cast<tcphdr *>(modified.data() + ip->ihl * 4);
      tcp->source = htons(entry.externalPort);
    } else if (proto == IPPROTO_UDP) {
      udphdr *udp = reinterpret_cast<udphdr *>(modified.data() + ip->ihl * 4);
      udp->source = htons(entry.externalPort);
    }

    ip->check = 0;
    ip->check = ipChecksum(ip, ip->ihl * 4);

    std::cout << "[SNAT] Reused mapping: " << entry.externalIp << ":"
              << entry.externalPort << "\n";
    return modified;
  }

  // 分配新端口并创建映射
  uint16_t externalPort = allocateExternalPort();
  std::string natKey = makeNatKey(publicIp_, externalPort, proto);
  natTable_[natKey] = NATEntry{srcIp, srcPort, publicIp_, externalPort, proto};
  reverseTable_[reverseKey] = natKey;

  in_addr newAddr;
  inet_aton(publicIp_.c_str(), &newAddr);
  ip->saddr = newAddr.s_addr;

  if (proto == IPPROTO_TCP) {
    tcphdr *tcp = reinterpret_cast<tcphdr *>(modified.data() + ip->ihl * 4);
    tcp->source = htons(externalPort);
  } else if (proto == IPPROTO_UDP) {
    udphdr *udp = reinterpret_cast<udphdr *>(modified.data() + ip->ihl * 4);
    udp->source = htons(externalPort);
  }

  ip->check = 0;
  ip->check = ipChecksum(ip, ip->ihl * 4);

  std::cout << "[SNAT] Mapped to: " << publicIp_ << ":" << externalPort << "\n";
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
  std::string key = makeNatKey(dstIp, dstPort, proto);

  auto it = natTable_.find(key);
  if (it == natTable_.end()) {
    return packet; // 没找到映射，不处理
  }

  const NATEntry &entry = it->second;

  std::cout << "[DNAT] Matched mapping: " << entry.internalIp << ":"
            << entry.internalPort << "\n";

  in_addr newAddr;
  inet_aton(entry.internalIp.c_str(), &newAddr);
  ip->daddr = newAddr.s_addr;

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
