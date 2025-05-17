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
  // 初始化监听接口
  PacketCapture cap;
  if (!cap.init("tun0"))
    return 1;

  // 初始化路由系统
  RoutingManager router;
  auto staticRouter = std::make_shared<StaticRouteProvider>();
  staticRouter->loadFromFile("config/routes.conf");
  router.addProvider(staticRouter);

  auto dynamicRouter =
      std::make_shared<DynamicRouteProvider>("tun0", "192.168.99.1");
  dynamicRouter->start();
  router.addProvider(dynamicRouter);

  // 初始化 NAT、防火墙、QoS
  NATManager nat;
  nat.setPublicIp("192.168.137.153");

  Firewall firewall;
  firewall.loadRules("config/firewall.rules");

  QoSManager qos;
  qos.loadRules("config/qos.rules");

  std::cout << "[Router] System started.\n";

  // 回包监听线程（从 raw socket 接收并写入 tun0）
  std::thread rawListener([&]() {
    while (true) {
      auto rawPkt = cap.readRawPacket();
      if (!rawPkt)
        continue;

      auto dnatted = nat.applyDNAT(*rawPkt);
      cap.writeToTun(dnatted);
    }
  });

  // 主循环处理来自 tun0 的出站流量
  while (true) {
    auto packet = cap.readPacket();
    if (!packet)
      continue;

    const std::string srcIp = extractSrcIp(*packet);
    const std::string dstIp = extractDstIp(*packet);

    std::cout << "[Cap] From " << srcIp << " to " << dstIp << "\n";

    // 防火墙过滤
    if (!firewall.allow(*packet)) {
      std::cout << "[Firewall] Blocked packet from " << srcIp << " to " << dstIp
                << "\n";
      continue;
    }

    // QoS 限速判断
    if (!qos.allow(*packet)) {
      std::cout << "[QoS] Rate limited packet from " << srcIp << "\n";
      continue;
    }

    // 出站流量（内网 -> 公网）
    if (isFromLan(srcIp) && !isFromLan(dstIp)) {
      auto route = router.lookupRoute(dstIp);
      if (!route) {
        std::cout << "[Router] No route for " << dstIp << "\n";
        continue;
      }
      std::cout << "[Router] <<< " << srcIp << "\n";
      auto snatted = nat.applySNAT(*packet);
      cap.writePacket(snatted); // 发往外网
    } else {
      cap.writePacket(*packet); // 非公网目的地，原样发出
    }
  }

  dynamicRouter->stop();
  rawListener.join();
  return 0;
}
