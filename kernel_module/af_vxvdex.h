#ifndef __LINUX_NET_AFVXVDEX_H
#define __LINUX_NET_AFVXVDEX_H
#include <linux/socket.h>
#include <linux/version.h>

#ifdef VXVDEX_STEALING
/* AF_NETBEUI seems to be unused */
#define AF_VXVDEX AF_NETBEUI
#define PF_VXVDEX AF_VXVDEX
#else
#error AF_VXVDEX has not been assigned yet
#endif

#endif
