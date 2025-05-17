#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class TcpRelay {
public:
  TcpRelay(const std::string &dstIp, uint16_t dstPort);
  ~TcpRelay();

  // 连接是否建立成功
  bool isConnected() const;

  // 从 TUN 收到数据，转发给 socket
  bool sendFromTun(const std::vector<uint8_t> &data);

  // 从 socket 收到数据，转发给 TUN
  std::optional<std::vector<uint8_t>> receiveFromSocket();

  // 获取 socket fd（用于 select/poll）
  int getSocketFd() const;

private:
  int sockFd_ = -1;
};
