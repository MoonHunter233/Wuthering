#include "routing/DynamicRouteProvider.h"
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sstream>
#include <sys/socket.h>
#include <unistd.h>

DynamicRouteProvider::DynamicRouteProvider(const std::string &iface,
                                           const std::string &localIp)
    : iface_(iface), localIp_(localIp), running_(false) {}

DynamicRouteProvider::~DynamicRouteProvider() { stop(); }

void DynamicRouteProvider::start() {
  running_ = true;
  sendThread_ = std::thread(&DynamicRouteProvider::sendLoop, this);
  recvThread_ = std::thread(&DynamicRouteProvider::receiveLoop, this);
}

void DynamicRouteProvider::stop() {
  running_ = false;
  if (sendThread_.joinable())
    sendThread_.join();
  if (recvThread_.joinable())
    recvThread_.join();
}

void DynamicRouteProvider::sendLoop() {
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    return;

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(54321);
  addr.sin_addr.s_addr = inet_addr("255.255.255.255");

  int broadcast = 1;
  setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

  while (running_) {
    std::this_thread::sleep_for(std::chrono::seconds(10));

    std::lock_guard<std::mutex> lock(routeMutex_);
    for (const auto &route : routeTable_) {
      std::string msg = route.dest + " " + route.netmask + " " + localIp_ +
                        " " + iface_ + " " + std::to_string(route.metric);
      sendto(sock, msg.c_str(), msg.size(), 0, (sockaddr *)&addr, sizeof(addr));
    }
  }
  close(sock);
}

void DynamicRouteProvider::receiveLoop() {
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
    return;

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(54321);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, (sockaddr *)&addr, sizeof(addr)) < 0) {
    close(sock);
    return;
  }

  char buffer[256];
  while (running_) {
    sockaddr_in sender{};
    socklen_t len = sizeof(sender);
    int bytes = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                         (sockaddr *)&sender, &len);
    if (bytes <= 0)
      continue;
    buffer[bytes] = 0;

    std::istringstream iss(buffer);
    RouteEntry route;
    std::string metricStr;
    iss >> route.dest >> route.netmask >> route.gateway >> route.iface >>
        metricStr;
    route.metric = std::stoi(metricStr);
    mergeRoutes({route}, inet_ntoa(sender.sin_addr));
  }
  close(sock);
}

void DynamicRouteProvider::mergeRoutes(const std::vector<RouteEntry> &newRoutes,
                                       const std::string &senderIp) {
  std::lock_guard<std::mutex> lock(routeMutex_);
  for (const auto &r : newRoutes) {
    bool updated = false;
    for (auto &existing : routeTable_) {
      if (existing.dest == r.dest && existing.netmask == r.netmask) {
        if (r.metric + 1 < existing.metric) {
          existing.gateway = senderIp;
          existing.metric = r.metric + 1;
          updated = true;
        }
        break;
      }
    }
    if (!updated) {
      RouteEntry newRoute = r;
      newRoute.gateway = senderIp;
      newRoute.metric += 1;
      routeTable_.push_back(newRoute);
    }
  }
}

std::optional<RouteEntry>
DynamicRouteProvider::lookup(const std::string &dstIp) {
  std::lock_guard<std::mutex> lock(routeMutex_);
  for (const auto &route : routeTable_) {
    if (match(dstIp, route)) {
      return route;
    }
  }
  return std::nullopt;
}

bool DynamicRouteProvider::match(const std::string &ip,
                                 const RouteEntry &route) {
  in_addr ipAddr, destAddr, maskAddr;
  inet_aton(ip.c_str(), &ipAddr);
  inet_aton(route.dest.c_str(), &destAddr);
  inet_aton(route.netmask.c_str(), &maskAddr);
  return (ipAddr.s_addr & maskAddr.s_addr) ==
         (destAddr.s_addr & maskAddr.s_addr);
}
