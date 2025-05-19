#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class PacketCapture {
public:
  bool init(const std::string &devName = "tun0");
  std::optional<std::vector<uint8_t>> readPacket(); // 从 TUN 读取
  std::optional<std::vector<uint8_t>> readRawPacket(); // 从 raw socket 读取回包
  bool
  writePacket(const std::vector<uint8_t> &packet); // 发往外网（raw socket）
  bool writeToTun(const std::vector<uint8_t> &packet); // 写回 TUN（发回客户端）
  bool sendViaInterface(const std::vector<uint8_t> &packet,
                        const std::string &gateway, const std::string &iface);
  std::string getInterfaceName() const;
  int getTunFd() const;

private:
  int tunFd_ = -1;
  int rawFd_ = -1;
  std::string ifName_;
};
