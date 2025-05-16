#include "routing/StaticRouteProvider.h"
#include <arpa/inet.h>
#include <fstream>
#include <iostream>
#include <sstream>

bool StaticRouteProvider::loadFromFile(const std::string &path) {
  std::ifstream in(path);
  if (!in) {
    std::cerr << "Failed to open route config: " << path << std::endl;
    return false;
  } else
    std::cout << "Load route config" << std::endl;

  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#')
      continue;
    std::istringstream ss(line);
    RouteEntry entry;
    ss >> entry.dest >> entry.netmask >> entry.gateway >> entry.iface;
    routes_.push_back(entry);
  }

  return true;
}

bool StaticRouteProvider::match(const std::string &ip,
                                const RouteEntry &route) {
  in_addr ipAddr, destAddr, maskAddr;
  inet_aton(ip.c_str(), &ipAddr);
  inet_aton(route.dest.c_str(), &destAddr);
  inet_aton(route.netmask.c_str(), &maskAddr);
  return (ipAddr.s_addr & maskAddr.s_addr) ==
         (destAddr.s_addr & maskAddr.s_addr);
}

std::optional<RouteEntry>
StaticRouteProvider::lookup(const std::string &dstIp) {
  for (const auto &route : routes_) {
    if (match(dstIp, route)) {
      return route;
    }
  }
  return std::nullopt;
}
