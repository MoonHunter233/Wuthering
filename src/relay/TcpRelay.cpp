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

  // 连接到本地 socks5 代理
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(7897); // Clash socks5 或 mixed-port
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

  if (connect(sockFd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    perror("[TcpRelay] connect socks5");
    close(sockFd_);
    sockFd_ = -1;
    return;
  }

  if (!socks5Connect(dstIp, dstPort)) {
    std::cerr << "[TcpRelay] socks5 handshake failed\n";
    close(sockFd_);
    sockFd_ = -1;
    return;
  }
  std::cout << "[TcpRelay] SOCKS5 connected to " << dstIp << ":" << dstPort
            << "\n";
}

TcpRelay::~TcpRelay() {
  if (sockFd_ >= 0)
    close(sockFd_);
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

// ====== SOCKS5 客户端简易握手 ======
bool TcpRelay::socks5Connect(const std::string &dstIp, uint16_t dstPort) {
  // 1. Greeting: VER, NMETHODS, METHODS
  uint8_t hello[3] = {0x05, 0x01, 0x00};
  if (write(sockFd_, hello, 3) != 3)
    return false;
  uint8_t helloResp[2];
  if (read(sockFd_, helloResp, 2) != 2 || helloResp[1] != 0x00)
    return false;

  // 2. Connect Request: VER, CMD=CONNECT, RSV, ATYP=IPv4, DST.ADDR, DST.PORT
  uint8_t req[10] = {0x05, 0x01, 0x00, 0x01};
  in_addr ip{};
  inet_pton(AF_INET, dstIp.c_str(), &ip);
  std::memcpy(req + 4, &ip.s_addr, 4);
  req[8] = (uint8_t)((dstPort >> 8) & 0xFF);
  req[9] = (uint8_t)(dstPort & 0xFF);
  if (write(sockFd_, req, 10) != 10)
    return false;
  uint8_t resp[10];
  if (read(sockFd_, resp, 10) != 10 || resp[1] != 0x00)
    return false;

  return true;
}
