#include "core/PacketCapture.h"
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

bool PacketCapture::init(const std::string &devName) {
  tunFd_ = open("/dev/net/tun", O_RDWR);
  if (tunFd_ < 0) {
    perror("open /dev/net/tun");
    return false;
  }

  struct ifreq ifr {};
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  std::strncpy(ifr.ifr_name, devName.c_str(), IFNAMSIZ);

  if (ioctl(tunFd_, TUNSETIFF, &ifr) < 0) {
    perror("ioctl TUNSETIFF");
    close(tunFd_);
    return false;
  }

  ifName_ = devName;
  std::cout << "[PacketCapture] Created TUN device: " << ifName_ << std::endl;
  return true;
}

std::optional<std::vector<uint8_t>> PacketCapture::readPacket() {
  uint8_t buffer[2000];
  int len = read(tunFd_, buffer, sizeof(buffer));
  if (len < 0) {
    perror("read");
    return std::nullopt;
  }
  return std::vector<uint8_t>(buffer, buffer + len);
}

bool PacketCapture::writePacket(const std::vector<uint8_t> &packet) {
  int written = write(tunFd_, packet.data(), packet.size());
  return written == packet.size();
}

std::string PacketCapture::getInterfaceName() const { return ifName_; }
