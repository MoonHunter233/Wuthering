#include "nat/NATManager.h"
#include "relay/TcpRelay.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

TcpRelay::TcpRelay(const std::string &dstIp, uint16_t dstPort, NATManager &nat,
                   const std::string &relayKey)
    : natManager_(nat), relayKey_(relayKey) {
  sockFd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (sockFd_ < 0) {
    perror("[TcpRelay] socket");
    return;
  }

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(dstPort);
  if (inet_pton(AF_INET, dstIp.c_str(), &addr.sin_addr) <= 0) {
    std::cerr << "[TcpRelay] Invalid IP: " << dstIp << "\n";
    close(sockFd_);
    sockFd_ = -1;
    return;
  }

  if (connect(sockFd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    perror("[TcpRelay] connect");
    close(sockFd_);
    sockFd_ = -1;
  } else {
    std::cout << "[TcpRelay] Connected to " << dstIp << ":" << dstPort << "\n";
  }
}

TcpRelay::~TcpRelay() {
  if (sockFd_ >= 0) {
    close(sockFd_);
  }
}

bool TcpRelay::isConnected() const { return sockFd_ >= 0; }

bool TcpRelay::sendPayload(const std::vector<uint8_t> &data) {
  if (sockFd_ < 0)
    return false;
  ssize_t written = write(sockFd_, data.data(), data.size());
  return written == static_cast<ssize_t>(data.size());
}

std::optional<std::vector<uint8_t>> TcpRelay::receivePayload() {
  if (sockFd_ < 0)
    return std::nullopt;

  uint8_t buffer[2000];
  ssize_t len = read(sockFd_, buffer, sizeof(buffer));
  if (len <= 0)
    return std::nullopt;

  // 使用 NATManager 获取原始源地址和端口
  std::string srcIp;
  uint16_t srcPort;
  if (!natManager_.getOriginalSource(relayKey_, srcIp, srcPort)) {
    std::cerr << "[TcpRelay] Failed to find original source for relayKey: "
              << relayKey_ << "\n";
    return std::nullopt;
  }

  // 构造 IP + TCP 报文（简化版本）
  std::vector<uint8_t> packet(sizeof(iphdr) + sizeof(tcphdr) + len);
  iphdr *ip = reinterpret_cast<iphdr *>(packet.data());
  tcphdr *tcp = reinterpret_cast<tcphdr *>(packet.data() + sizeof(iphdr));

  ip->version = 4;
  ip->ihl = 5;
  ip->tot_len = htons(packet.size());
  ip->ttl = 64;
  ip->protocol = IPPROTO_TCP;
  inet_pton(AF_INET, natManager_.getPublicIp().c_str(), &ip->saddr);
  inet_pton(AF_INET, srcIp.c_str(), &ip->daddr);

  tcp->source = htons(80); // 假设远端端口为 80
  tcp->dest = htons(srcPort);

  std::memcpy(packet.data() + sizeof(iphdr) + sizeof(tcphdr), buffer, len);

  return packet;
}

int TcpRelay::getSocketFd() const { return sockFd_; }
