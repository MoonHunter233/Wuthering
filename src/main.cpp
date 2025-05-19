#include "QoS/QoSManager.h"
#include "core/PacketCapture.h"
#include "core/RoutingManager.h"
#include "firewall/Firewall.h"
#include "nat/NATManager.h"
#include "routing/DynamicRouteProvider.h"
#include "routing/StaticRouteProvider.h"

#include <arpa/inet.h>
#include <iostream>
#include <memory>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <thread>

std::string extractDstIp(const std::vector<uint8_t> &packet) {
  const struct iphdr *iph =
      reinterpret_cast<const struct iphdr *>(packet.data());
  in_addr dst;
  dst.s_addr = iph->daddr;
  return std::string(inet_ntoa(dst));
}

std::string extractSrcIp(const std::vector<uint8_t> &packet) {
  const struct iphdr *iph =
      reinterpret_cast<const struct iphdr *>(packet.data());
  in_addr src;
  src.s_addr = iph->saddr;
  return std::string(inet_ntoa(src));
}

bool isFromLan(const std::string &ip) {
  return ip.rfind("192.168.", 0) == 0 || ip.rfind("10.", 0) == 0 ||
         ip.rfind("172.", 0) == 0;
}

int main() {
  PacketCapture cap;
  if (!cap.init("tun0"))
    return 1;

  RoutingManager router;
  auto staticRouter = std::make_shared<StaticRouteProvider>();
  staticRouter->loadFromFile("config/routes.conf");
  router.addProvider(staticRouter);

  auto dynamicRouter =
      std::make_shared<DynamicRouteProvider>("tun0", "192.168.99.1");
  dynamicRouter->start();
  router.addProvider(dynamicRouter);

  NATManager nat;
  nat.setPublicIp("wlan0");

  Firewall firewall;
  firewall.loadRules("config/firewall.rules");
  QoSManager qos;
  qos.loadRules("config/qos.rules");

  std::cout << "[Router] System started.\n";

  std::thread rawListener([&]() {
    while (true) {
      auto rawPkt = cap.readRawPacket();
      if (!rawPkt)
        continue;
      auto dnatted = nat.applyDNAT(*rawPkt);
      cap.writeToTun(dnatted);
    }
  });

  int tunFd = cap.getTunFd();

  while (true) {
    struct pollfd pfd = {tunFd, POLLIN, 0};
    int ret = poll(&pfd, 1, 100);
    if (ret < 0) {
      perror("poll");
      continue;
    }

    if (pfd.revents & POLLIN) {
      auto packet = cap.readPacket();
      if (!packet)
        continue;

      std::string srcIp = extractSrcIp(*packet);
      std::string dstIp = extractDstIp(*packet);
      const struct iphdr *iph =
          reinterpret_cast<const struct iphdr *>(packet->data());
      uint8_t proto = iph->protocol;

      std::cout << "[Cap] From " << srcIp << " to " << dstIp << "\n";

      if (!firewall.allow(*packet)) {
        std::cout << "[Firewall] Blocked packet from " << srcIp << " to "
                  << dstIp << "\n";
        continue;
      }

      if (!qos.allow(*packet)) {
        std::cout << "[QoS] Rate limited packet from " << srcIp << "\n";
        continue;
      }

      if (isFromLan(srcIp) && !isFromLan(dstIp)) {
        auto route = router.lookupRoute(dstIp);
        if (!route) {
          std::cout << "[Router] No route for " << dstIp << "\n";
          continue;
        }
        std::cout << "[Router] Route to " << dstIp << " via " << route->gateway
                  << " on " << route->iface << "\n";
        auto snatted = nat.applySNAT(*packet);
        cap.sendViaInterface(snatted, route->gateway, route->iface);
      } else {
        cap.writePacket(*packet);
      }
    }
  }

  dynamicRouter->stop();
  rawListener.join();
  return 0;
}
