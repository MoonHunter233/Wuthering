#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class TcpRelay {
public:
  TcpRelay(const std::string &dstIp, uint16_t dstPort);
  ~TcpRelay();

  bool isConnected() const;

  // 透传应用层 payload
  bool sendPayload(const std::vector<uint8_t> &data);
  std::optional<std::vector<uint8_t>> receivePayload();

  int getSocketFd() const;

private:
  int sockFd_ = -1;
  bool socks5Connect(const std::string &dstIp, uint16_t dstPort);
};
