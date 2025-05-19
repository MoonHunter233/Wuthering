#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class TcpRelay {
public:
  // 构造函数接收目标地址和端口，连接 SOCKS5 代理
  TcpRelay(const std::string &dstIp, uint16_t dstPort);
  ~TcpRelay();

  // 检查 SOCKS5 连接是否成功
  bool isConnected() const;

  // 发送 payload 数据
  bool sendPayload(const std::vector<uint8_t> &data);

  // 接收 payload 数据
  std::optional<std::vector<uint8_t>> receivePayload();

  // 获取 socket 文件描述符（供 poll/select 使用）
  int getSocketFd() const;

private:
  int sockFd_ = -1;

  // 执行 SOCKS5 握手与目标连接建立
  bool socks5Connect(const std::string &dstIp, uint16_t dstPort);
};
