#include "core/RoutingManager.h"

void RoutingManager::addProvider(std::shared_ptr<IRouteProvider> provider) {
  providers_.push_back(std::move(provider));
}

std::optional<RouteEntry>
RoutingManager::lookupRoute(const std::string &dstIp) {
  for (const auto &provider : providers_) {
    auto result = provider->lookup(dstIp);
    if (result.has_value()) {
      return result;
    }
  }
  return std::nullopt;
}
