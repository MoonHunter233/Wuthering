#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class PacketCapture {
public:
  bool init(const std::string &devName = "tun0");
  std::optional<std::vector<uint8_t>> readPacket();
  bool writePacket(const std::vector<uint8_t> &packet);
  std::string getInterfaceName() const;

private:
  int tunFd_ = -1;
  std::string ifName_;
};
