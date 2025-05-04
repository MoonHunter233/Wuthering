#pragma once
#include "IRouteProvider.h"
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

class DynamicRouteProvider : public IRouteProvider {
public:
  DynamicRouteProvider(const std::string &iface, const std::string &localIp);
  ~DynamicRouteProvider();

  void start();
  void stop();

  std::optional<RouteEntry> lookup(const std::string &dstIp) override;

private:
  void sendLoop();
  void receiveLoop();
  void mergeRoutes(const std::vector<RouteEntry> &newRoutes,
                   const std::string &senderIp);
  bool match(const std::string &ip, const RouteEntry &route);

  std::string iface_;
  std::string localIp_;
  std::vector<RouteEntry> routeTable_;
  std::mutex routeMutex_;

  std::thread sendThread_;
  std::thread recvThread_;
  std::atomic<bool> running_;
};
