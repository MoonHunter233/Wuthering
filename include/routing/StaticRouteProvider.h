#pragma once
#include "IRouteProvider.h"
#include <vector>

class StaticRouteProvider : public IRouteProvider {
public:
  bool loadFromFile(const std::string &path);
  std::optional<RouteEntry> lookup(const std::string &dstIp) override;

private:
  std::vector<RouteEntry> routes_;
  bool match(const std::string &ip, const RouteEntry &route);
};
