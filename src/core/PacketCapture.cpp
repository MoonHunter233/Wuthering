#include "core/PacketCapture.h"
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

bool PacketCapture::init(const std::string &devName) {
  // 创建 raw socket
  rawFd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
  if (rawFd_ < 0) {
    perror("socket rawFd_");
    return false;
  }

  // 绑定到指定接口（例如 veth-host）
  struct sockaddr_ll sll = {};
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_IP);
  sll.sll_ifindex = if_nametoindex(devName.c_str());
  if (sll.sll_ifindex == 0 ||
      bind(rawFd_, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    perror("bind rawFd_");
    close(rawFd_);
    return false;
  }

  ifName_ = devName;
  std::cout << "[PacketCapture] Bound to raw interface: " << ifName_
            << std::endl;
  return true;
}

std::optional<std::vector<uint8_t>> PacketCapture::readPacket() {
  uint8_t buffer[2000];
  int len = recvfrom(rawFd_, buffer, sizeof(buffer), 0, nullptr, nullptr);
  if (len < 0) {
    perror("recvfrom rawFd");
    return std::nullopt;
  }
  return std::vector<uint8_t>(buffer + 14, buffer + len); // 跳过以太网头
}

bool PacketCapture::writePacket(const std::vector<uint8_t> &packet) {
  // 使用原始 socket 发包（IP 层发包）
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (sock < 0) {
    perror("socket IPPROTO_RAW");
    return false;
  }
  int one = 1;
  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

  struct sockaddr_in dst {};
  const iphdr *ip = reinterpret_cast<const iphdr *>(packet.data());
  dst.sin_family = AF_INET;
  dst.sin_addr.s_addr = ip->daddr;

  int sent = sendto(sock, packet.data(), packet.size(), 0,
                    (struct sockaddr *)&dst, sizeof(dst));
  close(sock);
  return sent == (int)packet.size();
}

std::string PacketCapture::getInterfaceName() const { return ifName_; }
