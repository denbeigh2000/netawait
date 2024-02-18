#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>

struct route_request {
  struct rt_msghdr rtm;
  struct sockaddr_in dst;
  struct sockaddr_in mask;
};
