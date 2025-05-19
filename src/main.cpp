#include "QoS/QoSManager.h"
#include "core/PacketCapture.h"
#include "core/RoutingManager.h"
#include "firewall/Firewall.h"
#include "nat/NATManager.h"
#include "relay/TcpRelay.h"
#include "routing/DynamicRouteProvider.h"
#include "routing/StaticRouteProvider.h"

#include <arpa/inet.h>
#include <iostream>
#include <memory>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <thread>
#include <unordered_map>

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

std::string makeRelayKey(const std::string &ip, uint16_t port, uint8_t proto) {
  return ip + ":" + std::to_string(port) + ":" + std::to_string(proto);
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
  nat.setPublicIp("192.168.137.153");

  Firewall firewall;
  firewall.loadRules("config/firewall.rules");

  QoSManager qos;
  qos.loadRules("config/qos.rules");

  std::unordered_map<std::string, std::unique_ptr<TcpRelay>> relayMap;
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
    std::vector<struct pollfd> pfds;
    pfds.push_back({tunFd, POLLIN, 0});
    std::vector<std::string> keys;

    for (auto &[key, relay] : relayMap) {
      int fd = relay->getSocketFd();
      if (fd >= 0) {
        pfds.push_back({fd, POLLIN, 0});
        keys.push_back(key);
      }
    }

    int ret = poll(pfds.data(), pfds.size(), 100);
    if (ret < 0) {
      perror("poll");
      continue;
    }

    if (pfds[0].revents & POLLIN) {
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

        std::cout << "[Router] <<< " << srcIp << "\n";
        auto snatted = nat.applySNAT(*packet);

        const iphdr *snatIp = reinterpret_cast<const iphdr *>(snatted.data());
        uint16_t dstPort = 0, relaySrcPort = 0;
        std::string relaySrcIp;

        if (proto == IPPROTO_TCP &&
            snatted.size() >= snatIp->ihl * 4 + sizeof(tcphdr)) {
          auto *tcp = reinterpret_cast<const tcphdr *>(snatted.data() +
                                                       snatIp->ihl * 4);
          dstPort = ntohs(tcp->dest);
          relaySrcPort = ntohs(tcp->source);
        }

        relaySrcIp = inet_ntoa(*(in_addr *)&snatIp->saddr);
        std::string key = makeRelayKey(relaySrcIp, relaySrcPort, proto);

        if (relayMap.find(key) == relayMap.end()) {
          auto relay = std::make_unique<TcpRelay>(dstIp, dstPort, nat, key);
          if (!relay->isConnected()) {
            std::cout << "[Relay] Failed to connect to " << dstIp << ":"
                      << dstPort << "\n";
            continue;
          }
          relayMap[key] = std::move(relay);
        }
        relayMap[key]->sendPayload(snatted);
      } else {
        cap.writePacket(*packet);
      }
    }

    for (size_t i = 1; i < pfds.size(); ++i) {
      if (pfds[i].revents & POLLIN) {
        auto &relay = relayMap[keys[i - 1]];
        auto back = relay->receivePayload();
        if (back) {
          cap.writePacket(*back);
        } else {
          std::cout << "[Relay] Connection closed or failed for key: "
                    << keys[i - 1] << ", removing.\n";
          relayMap.erase(keys[i - 1]);
        }
      }
    }
  }

  dynamicRouter->stop();
  rawListener.join();
  return 0;
}
