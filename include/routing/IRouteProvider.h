#pragma once
#include <optional>
#include <string>

struct RouteEntry {
  std::string dest;
  std::string netmask;
  std::string gateway;
  std::string iface;
};

class IRouteProvider {
public:
  virtual ~IRouteProvider() = default;
  virtual std::optional<RouteEntry> lookup(const std::string &dstIp) = 0;
};
