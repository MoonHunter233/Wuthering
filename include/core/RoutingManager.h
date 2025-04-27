#pragma once
#include "routing/IRouteProvider.h"
#include <memory>
#include <vector>

class RoutingManager {
public:
  void addProvider(std::shared_ptr<IRouteProvider> provider);
  std::optional<RouteEntry> lookupRoute(const std::string &dstIp);

private:
  std::vector<std::shared_ptr<IRouteProvider>> providers_;
};
