#include "nat/NATManager.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netinet/ip.h>

static uint16_t ipChecksum(void *vdata, size_t length);

void NATManager::setPublicIp(const std::string &ip) { publicIp_ = ip; }

std::vector<uint8_t> NATManager::applySNAT(const std::vector<uint8_t> &packet) {
  std::vector<uint8_t> modified = packet;
  struct iphdr *ip = reinterpret_cast<struct iphdr *>(modified.data());

  in_addr newAddr;
  inet_aton(publicIp_.c_str(), &newAddr);

  ip->saddr = newAddr.s_addr;
  ip->check = 0;
  ip->check = ipChecksum(ip, ip->ihl * 4);

  return modified;
}

// same file or shared header
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
