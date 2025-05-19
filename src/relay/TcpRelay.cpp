#include "relay/TcpRelay.h"
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

TcpRelay::TcpRelay(const std::string &dstIp, uint16_t dstPort) {
  sockFd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (sockFd_ < 0) {
    perror("[TcpRelay] socket");
    return;
  }

  if (!socks5Connect(dstIp, dstPort)) {
    close(sockFd_);
    sockFd_ = -1;
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

  return std::vector<uint8_t>(buffer, buffer + len);
}

int TcpRelay::getSocketFd() const { return sockFd_; }

bool TcpRelay::socks5Connect(const std::string &dstIp, uint16_t dstPort) {
  sockaddr_in proxyAddr{};
  proxyAddr.sin_family = AF_INET;
  proxyAddr.sin_port = htons(7897); // Clash 本地代理端口
  inet_pton(AF_INET, "127.0.0.1", &proxyAddr.sin_addr);

  if (connect(sockFd_, reinterpret_cast<sockaddr *>(&proxyAddr),
              sizeof(proxyAddr)) < 0) {
    perror("[TcpRelay] connect to proxy");
    return false;
  }

  // 协议阶段 1: 协议版本 + 支持的方法数 + 方法
  uint8_t request1[] = {0x05, 0x01, 0x00}; // SOCKS5, 1 method, no auth
  if (write(sockFd_, request1, sizeof(request1)) != sizeof(request1))
    return false;

  uint8_t response1[2];
  if (read(sockFd_, response1, 2) != 2 || response1[1] != 0x00)
    return false;

  // 协议阶段 2: 连接请求
  in_addr addr;
  inet_pton(AF_INET, dstIp.c_str(), &addr);
  uint8_t request2[10];
  request2[0] = 0x05; // version
  request2[1] = 0x01; // connect
  request2[2] = 0x00; // reserved
  request2[3] = 0x01; // IPv4
  memcpy(request2 + 4, &addr, 4);
  request2[8] = dstPort >> 8;
  request2[9] = dstPort & 0xff;

  if (write(sockFd_, request2, sizeof(request2)) != sizeof(request2))
    return false;

  uint8_t response2[10];
  if (read(sockFd_, response2, 10) != 10 || response2[1] != 0x00)
    return false;

  std::cout << "[TcpRelay] Connected via SOCKS5 to " << dstIp << ":" << dstPort
            << "\n";
  return true;
}
