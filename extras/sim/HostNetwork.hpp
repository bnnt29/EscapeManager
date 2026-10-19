#pragma once

// Picks the LAN address of a PC host (simulator, serial host) for UDP discovery and mDNS.
//
// Discovery needs an interface that can BROADCAST and whose address is the source address
// of the datagrams: receivers drop announcements whose "ip" differs from the sender
// (PROTOCOL.md 4.3). A plain route lookup is not enough - VPNs such as Tailscale or
// WireGuard install policy routes that catch every destination, which would select a
// point-to-point tunnel address that no device on the LAN can see.
//
// POSIX only (getifaddrs); the ESP32 firmware gets its address from the Wi-Fi driver.

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

namespace Escape {

struct HostInterface {
  uint32_t ip = 0x7F000001;       // host byte order
  uint32_t broadcast = 0x7FFFFFFFu; // loopback: simulators on one PC still find each other
  std::string name = "lo";
};

namespace HostNetworkDetail {

// Source address the kernel would use towards a public destination (nothing is sent).
inline uint32_t routedSourceIp() {
  const int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return 0;
  sockaddr_in remote;
  memset(&remote, 0, sizeof(remote));
  remote.sin_family = AF_INET;
  remote.sin_port = htons(80);
  inet_pton(AF_INET, "192.0.2.1", &remote.sin_addr); // TEST-NET-1
  uint32_t ip = 0;
  if (connect(fd, (sockaddr *)&remote, sizeof(remote)) == 0) {
    sockaddr_in local;
    socklen_t len = sizeof(local);
    if (getsockname(fd, (sockaddr *)&local, &len) == 0) ip = ntohl(local.sin_addr.s_addr);
  }
  close(fd);
  return ip;
}

// Bridges of container/VM tools are broadcast-capable but rarely the venue network.
inline bool looksVirtual(const char *name) {
  static const char *const prefixes[] = {"docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "lxc", "lxd", "cni", "flannel", "podman"};
  for (const char *p : prefixes) {
    if (strncmp(name, p, strlen(p)) == 0) return true;
  }
  return false;
}

} // namespace HostNetworkDetail

// Best interface for discovery: the routed one if it can broadcast, otherwise the first
// running broadcast-capable physical interface. Falls back to loopback.
inline HostInterface detectLanInterface() {
  HostInterface best;
  ifaddrs *list = nullptr;
  if (getifaddrs(&list) != 0) return best;
  const uint32_t routed = HostNetworkDetail::routedSourceIp();
  int bestScore = -1;
  for (ifaddrs *it = list; it; it = it->ifa_next) {
    if (!it->ifa_addr || !it->ifa_netmask || it->ifa_addr->sa_family != AF_INET) continue;
    const unsigned flags = it->ifa_flags;
    if (!(flags & IFF_UP) || !(flags & IFF_RUNNING) || !(flags & IFF_BROADCAST)) continue;
    if (flags & (IFF_LOOPBACK | IFF_POINTOPOINT)) continue;
    const uint32_t addr = ntohl(((sockaddr_in *)it->ifa_addr)->sin_addr.s_addr);
    const uint32_t mask = ntohl(((sockaddr_in *)it->ifa_netmask)->sin_addr.s_addr);
    if ((addr >> 16) == 0xA9FE) continue; // 169.254/16 link-local: no DHCP lease
    int score = 1;
    if (!HostNetworkDetail::looksVirtual(it->ifa_name)) score += 2;
    if (addr == routed) score += 4;
    if (score > bestScore) {
      bestScore = score;
      best.ip = addr;
      best.broadcast = addr | ~mask;
      best.name = it->ifa_name;
    }
  }
  freeifaddrs(list);
  return best;
}

// Directed broadcast of the interface that owns `ip`; 0 if no interface has it.
inline uint32_t broadcastForIp(uint32_t ip) {
  uint32_t result = 0;
  ifaddrs *list = nullptr;
  if (getifaddrs(&list) != 0) return result;
  for (ifaddrs *it = list; it; it = it->ifa_next) {
    if (!it->ifa_addr || !it->ifa_netmask || it->ifa_addr->sa_family != AF_INET) continue;
    const uint32_t addr = ntohl(((sockaddr_in *)it->ifa_addr)->sin_addr.s_addr);
    if (addr != ip) continue;
    const uint32_t mask = ntohl(((sockaddr_in *)it->ifa_netmask)->sin_addr.s_addr);
    if (!(it->ifa_flags & IFF_POINTOPOINT)) result = addr | ~mask;
    break;
  }
  freeifaddrs(list);
  return result;
}

} // namespace Escape
