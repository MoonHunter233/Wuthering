#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class PacketCapture {
public:
  bool
  init(const std::string &devName = "veth-host"); // 初始化 raw socket 绑定设备
  std::optional<std::vector<uint8_t>> readPacket(); // 从 raw socket 读取 IP 包
  bool writePacket(const std::vector<uint8_t> &packet); // 发送 IP 包到外网

  std::string getInterfaceName() const;

private:
  int rawFd_ = -1;
  std::string ifName_;
};
