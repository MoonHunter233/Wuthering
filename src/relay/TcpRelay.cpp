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

bool TcpRelay::sendFromTun(const std::vector<uint8_t> &data) {
  if (sockFd_ < 0)
    return false;
  ssize_t written = write(sockFd_, data.data(), data.size());
  return written == static_cast<ssize_t>(data.size());
}

std::optional<std::vector<uint8_t>> TcpRelay::receiveFromSocket() {
  if (sockFd_ < 0)
    return std::nullopt;

  uint8_t buffer[2000];
  ssize_t len = read(sockFd_, buffer, sizeof(buffer));
  if (len <= 0)
    return std::nullopt;

  return std::vector<uint8_t>(buffer, buffer + len);
}

int TcpRelay::getSocketFd() const { return sockFd_; }
