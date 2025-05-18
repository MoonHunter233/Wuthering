#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class NATManager; // 前向声明，避免循环依赖

class TcpRelay {
public:
  TcpRelay(const std::string &dstIp, uint16_t dstPort, NATManager &nat,
           const std::string &relayKey);
  ~TcpRelay();

  // 判断连接是否成功建立
  bool isConnected() const;

  // 向目标服务器发送 payload（来自 NAT 转换后的包体）
  bool sendPayload(const std::vector<uint8_t> &data);

  // 从目标服务器接收数据，并构造完整回包返回
  std::optional<std::vector<uint8_t>> receivePayload();

  // 获取 socket fd 供 poll/select 使用
  int getSocketFd() const;

private:
  int sockFd_ = -1;
  std::string relayKey_;
  NATManager &natManager_;
};
