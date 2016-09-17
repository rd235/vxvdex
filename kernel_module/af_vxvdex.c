/*
 * Main vxvdex networking module
 *  (part of the View-OS project: wiki.virtualsquare.org) 
 *
 * Copyright (C) 2016   Renzo Davoli (renzo@cs.unibo.it)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/socket.h>
#include <linux/namei.h>
#include <linux/poll.h>
#include <linux/un.h>
#include <linux/list.h>
#include <linux/mount.h>
#include <linux/version.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/ipv6.h>
#include <linux/igmp.h>
#include <net/ipv6.h>
#include "af_vxvdex.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Renzo Davoli, VirtualSquare");
MODULE_DESCRIPTION("VXVDEX Kernel Module");

#define DFL_MAXTTL 1
#define DFL_MINGID 1000
static int maxttl = DFL_MAXTTL;
static int mingid = DFL_MINGID;
static int ifindex = 0;

module_param(maxttl,int,S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(maxttl,"Max TTL for vxvdex");
module_param(mingid,int,S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(mingid,"min allowed gid");
module_param(ifindex,int,S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(ifindex,"index of net interface");

struct vxvdex_sock {
	struct sock  sk;
	struct socket *lower_sock;
	uint64_t vxhdr;
};

struct vxvde_hdr {
	unsigned char flags;
	unsigned char priv1[3];
	unsigned char id[3];
	unsigned char priv2[1];
};

#define hton24(p, v) { \
	p[0] = (((v) >> 16) & 0xFF); \
	p[1] = (((v) >> 8) & 0xFF); \
	p[2] = ((v) & 0xFF); \
}

/* convert the VXVDE 8 byte header in a
	 unsigned 64bit integer, to speed up the comparison */
static uint64_t vid2uint64(int vid) {
	union {
		struct vxvde_hdr vhdr;
		uint64_t ihdr;
	} u;
	u.ihdr = 0;
	u.vhdr.flags = (1 << 3);
	hton24(u.vhdr.id, vid);
	return(u.ihdr);
}

static inline struct vxvdex_sock *vxvdex_sk(const struct sock *sk)
{
	return (struct vxvdex_sock *)sk;
}

/* check if the three final bytes of an address are consistent with the vni */
static inline int vxvde_vni_addr_ck(uint64_t vxhdr, void *ipaddr, size_t len) {
	if (len > 3) {
		char *tail = ((char *) ipaddr) + (len - 3);
		union {
			struct vxvde_hdr vhdr;
			uint64_t ihdr;
		} u;
		u.ihdr = vxhdr;
		return memcmp(u.vhdr.id, tail, 3);
	} else
		return -1;
}

/* check_ttl returns a valid ttl value,
	 inside the valid range and limited by maxttl */
static inline int check_ttl(int newttl) {
	if (newttl > maxttl)
		newttl = maxttl;
	if (newttl < 1)
		return 1;
	if (newttl > 255)
		return 255;
	return  newttl;
}

/* get_ifindex returns ifindex if ifindex is zero (undefined) or 
	 if it is the index of a valid existing interface, -1 otherwise */
static inline int get_ifindex(void) {
	if (ifindex != 0) {
		struct net_device *dev = dev_get_by_index(&init_net, ifindex);
		if (!dev)
			return -1;
		dev_put(dev);
	}
	return ifindex;
}

/* bind permits two kinds of address assignments:
	 - if port != 0, only multicast IP addresses whose last three bytes are equal to the vni
	 are allowed (224-239.a,b,c ffxx:.....:xABC where abc and ABC are the three bytes of vni
	either in decimal notation (small letters), or in exadecimal (capital letters)).
	 - if port == 0, any IP address fit. */

static int vxvdex_bind(struct socket *sock, struct sockaddr *addr, int addr_len) {
	struct sock *sk = sock->sk;
	struct vxvdex_sock *vsk=vxvdex_sk(sk);
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
		if (addr4->sin_port != 0) {
			struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
			if (!ipv4_is_multicast(addr4->sin_addr.s_addr) || 
					vxvde_vni_addr_ck(vsk->vxhdr, &addr4->sin_addr, sizeof(addr4->sin_addr)))
				return -EPERM;
		}
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
		if (addr6->sin6_port != 0) {
			if (!ipv6_addr_is_multicast(&addr6->sin6_addr) || 
					vxvde_vni_addr_ck(vsk->vxhdr, &addr6->sin6_addr, sizeof(addr6->sin6_addr)))
				return -EPERM;
		}
	} else
		return -EINVAL;
	if (likely(vsk->lower_sock && vsk->lower_sock->sk))
		vsk->lower_sock->sk->sk_reuse = SK_CAN_REUSE;
	return vsk->lower_sock->ops->bind(vsk->lower_sock, addr, addr_len);
}

static int vxvdex_getname(struct socket *sock, struct sockaddr *addr,
		int *addr_len, int peer)  {
	struct sock *sk = sock->sk;
	struct vxvdex_sock *vsk=vxvdex_sk(sk);
	return vsk->lower_sock->ops->getname(vsk->lower_sock, addr, addr_len, peer);
}

static unsigned int vxvdex_poll(struct file *file, struct socket *sock,
		poll_table *wait) {
	struct sock *sk = sock->sk;
	struct vxvdex_sock *vsk=vxvdex_sk(sk);
	return vsk->lower_sock->ops->poll(file, vsk->lower_sock, wait);
}

#define get_optval(val, optval, optlen) \
	({ \
	 int __err = -EFAULT; \
	 if ((optlen) >= sizeof(int)) { \
	 __err = get_user((val), (int __user *) (optval)); \
	 } else if ((optlen) >= sizeof(char)) { \
	 unsigned char __ucval; \
	 __err = get_user(__ucval, (unsigned char __user *) (optval)); \
	 (val) = __ucval; \
	 } \
	 __err; \
	 })

/* setsockopt allows only the minimal set of options required by vxvdex,
	 as required by the principle of least privilege */
/* setsockopt: IP_ADD_MEMBERSHIP/IPV6_ADD_MEMBERSHIP allow only multicast address
	 whose last three bytes are equal to the vni */
static int vxvdex_setsockopt(struct socket *sock, int level, int optname,
		char __user *optval, unsigned int optlen) {
	struct sock *sk = sock->sk;
	struct vxvdex_sock *vsk=vxvdex_sk(sk);
	struct sock *lower_sk = vsk->lower_sock->sk;
	unsigned short af_family = lower_sk->sk_family;
	int val = 0;
	if (unlikely(lower_sk == NULL))
		return -EINVAL;
	if (level == SOL_SOCKET) {
		int err = 0;
		switch (optname) {
			case SO_RCVBUF:
				if (get_optval(val, optval, optlen))
					return -EFAULT;
		}
		lock_sock(lower_sk);
		switch (optname) {
			case SO_RCVBUF:
				val = min_t(u32, val, sysctl_rmem_max);
				lower_sk->sk_userlocks |= SOCK_RCVBUF_LOCK;
				lower_sk->sk_rcvbuf = max_t(u32, val * 2, SOCK_MIN_RCVBUF);
			break;
		}
		release_sock(lower_sk);
		return err;
	} else if (af_family == AF_INET && level == SOL_IP) {
		struct inet_sock *inet = inet_sk(lower_sk);
		int err = 0;
		switch (optname) {
			case IP_TTL:
			case IP_MULTICAST_TTL:
			case IP_PKTINFO:
				if (get_optval(val, optval, optlen))
					return -EFAULT;
		}
		lock_sock(lower_sk);
		switch (optname) {
			case IP_ADD_MEMBERSHIP:
			case IP_DROP_MEMBERSHIP:
				{
					struct ip_mreqn mreq;
					int ifindex = get_ifindex();
					if (ifindex < 0) {
						err = EADDRNOTAVAIL;
						break;
					}
					if (optlen < sizeof(mreq)) {
						err = EINVAL;
						break;
					}
					if (copy_from_user(&mreq, optval, sizeof(mreq))) {
						err = -EFAULT;
						break;
					}
					if (vxvde_vni_addr_ck(vsk->vxhdr, &mreq.imr_multiaddr, sizeof(mreq.imr_multiaddr)) != 0) {
						err = -EPERM;
						break;
					}
					if (inet->is_icsk) {
						err = -EPROTO;
						break;
					}
					mreq.imr_address.s_addr = 0;
					mreq.imr_ifindex = ifindex;

					rtnl_lock();
					if (optname == IP_ADD_MEMBERSHIP)
						err = ip_mc_join_group(lower_sk, &mreq);
					else
						err = ip_mc_leave_group(lower_sk, &mreq);
					rtnl_unlock();
					break;
				}
			case IP_TTL:
				inet->uc_ttl = check_ttl(val);
				break;
			case IP_MULTICAST_TTL:
				inet->mc_ttl = check_ttl(val);
				break;
			case IP_PKTINFO:
				if (val)
					inet->cmsg_flags |= IP_CMSG_PKTINFO;
				else
					inet->cmsg_flags &= ~IP_CMSG_PKTINFO;
				break;
			default:
				err = -ENOPROTOOPT;
		}
		release_sock(lower_sk);
		return err;
	} else if (af_family == AF_INET6 && level == SOL_IPV6) {
		struct ipv6_pinfo *np = inet6_sk(lower_sk);
		int err = 0;
		switch (optname) {
			case IPV6_MULTICAST_HOPS:
			case IPV6_RECVPKTINFO:
				if (get_optval(val, optval, optlen))
					return -EFAULT;
		}
		lock_sock(lower_sk);
		switch (optname) {
			case IPV6_ADD_MEMBERSHIP:
			case IPV6_DROP_MEMBERSHIP:
				{
					struct ipv6_mreq mreq;
					int ifindex = get_ifindex();
					if (ifindex < 0) {
						err = EADDRNOTAVAIL;
						break;
					}
					if (optlen < sizeof(mreq)) {
						err = EINVAL;
						break;
					}
					if (copy_from_user(&mreq, optval, sizeof(mreq))) {
						err = -EFAULT;
						break;
					}
					if (vxvde_vni_addr_ck(vsk->vxhdr, &mreq.ipv6mr_multiaddr, sizeof(mreq.ipv6mr_multiaddr)) != 0) {
						err = -EPERM;
						break;
					}
					if (inet_sk(lower_sk)->is_icsk) {
						err = -EPROTO;
						break;
					}

					rtnl_lock();
					if (optname == IPV6_ADD_MEMBERSHIP)
						err = ipv6_sock_mc_join(lower_sk, ifindex, &mreq.ipv6mr_multiaddr);
					else
						err = ipv6_sock_mc_drop(lower_sk, ifindex, &mreq.ipv6mr_multiaddr);
					rtnl_unlock();
					break;
				}
			case IPV6_MULTICAST_HOPS:
				np->hop_limit =  check_ttl(val);
				break;
			case IPV6_RECVPKTINFO:
				np->rxopt.bits.rxinfo = (val != 0);
				break;
			default:
				err = -ENOPROTOOPT;
		}
		release_sock(lower_sk);
		return err;
	} else
		return ENOPROTOOPT;
}

static int vxvdex_getsockopt(struct socket *sock, int level, int optname,
		char __user *optval, int __user *optlen) {
	struct sock *sk = sock->sk;
	struct vxvdex_sock *vsk=vxvdex_sk(sk);
	return vsk->lower_sock->ops->getsockopt(vsk->lower_sock, level, optname, optval,optlen);
}

static int vxvdex_sendmsg(struct socket *sock,
		struct msghdr *msg, size_t len) {
	struct sock *sk = sock->sk;
	struct vxvdex_sock *vsk=vxvdex_sk(sk);
	uint64_t vxhdr;
	const struct iovec *liov = msg->msg_iter.iov;
	if (liov == NULL || liov->iov_len < 8)
		return -EINVAL;
	/* check if the vxvde header has the right value */
	if (copy_from_user(&vxhdr, liov->iov_base, sizeof(vxhdr)) != 0)
		return -EINVAL; 
	//printk("vxvdex_sendmsg %llx %llx\n", vxhdr, vsk->vxhdr);
	if (vxhdr != vsk->vxhdr)
		return -EACCES;
	return vsk->lower_sock->ops->sendmsg(vsk->lower_sock, msg, len);
}

static int vxvdex_recvmsg(struct socket *sock,
		struct msghdr *msg, size_t len, int flags) {
	struct sock *sk = sock->sk;
	struct vxvdex_sock *vsk=vxvdex_sk(sk);
	int rv;
	uint64_t vxhdr;
	const struct iovec *liov = msg->msg_iter.iov;
	if (liov == NULL || liov->iov_len < 8)
		return -EINVAL;
	rv = vsk->lower_sock->ops->recvmsg(vsk->lower_sock, msg, len, flags);
	/* check if the vxvde header has the right value */
	if (copy_from_user(&vxhdr, liov->iov_base, sizeof(vxhdr)) != 0)
		return -EINVAL;
	//printk("vxvdex_recvmsg %llx %llx\n", vxhdr, vsk->vxhdr);
	if (vxhdr != vsk->vxhdr)
		return -EAGAIN;  /* EACCESS can break some support */
	return rv;
}

static int vxvdex_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct vxvdex_sock *vsk=vxvdex_sk(sk);
	sock_release(vsk->lower_sock);
	sock_put(sk);
	return 0;
}

static const struct proto_ops vxvdex_ops = {
	.family = PF_VXVDEX,
	.owner =  THIS_MODULE,
	.release =  vxvdex_release,
	.bind =   vxvdex_bind,
	.connect =  sock_no_connect,
	.socketpair = sock_no_socketpair,
	.accept = sock_no_accept,
	.getname =  vxvdex_getname,
	.poll =   vxvdex_poll,
	.ioctl =  sock_no_ioctl,
	.listen = sock_no_listen,
	.shutdown = sock_no_shutdown,
	.setsockopt = vxvdex_setsockopt,
	.getsockopt = vxvdex_getsockopt,
	.sendmsg =  vxvdex_sendmsg,
	.recvmsg =  vxvdex_recvmsg,
	.mmap =   sock_no_mmap,
	.sendpage = sock_no_sendpage,
};

static struct proto vxvdex_proto = {
	.name   = "VXVDEX",
	.owner    = THIS_MODULE,
	.obj_size = sizeof(struct vxvdex_sock),
};

/* create a vxvdex socket: 
	 type is SOCK_DGRAM
	 protocol is either AF_INET or AF_INET6 */
static int vxvdex_create(struct net *net, struct socket *sock,
		int protocol, int kern) {
	struct vxvdex_sock *sk;
	int err=EAFNOSUPPORT;
	int ifindex = get_ifindex();
	kgid_t egid = current_egid();

	if (sock->type != SOCK_DGRAM)
		return -EPROTOTYPE;
	if (protocol != AF_INET && protocol != AF_INET6)
		return -EPROTONOSUPPORT;
	if (egid.val < mingid)
		return -EPERM;
	if (ifindex < 0)
		return -EADDRNOTAVAIL;
	err = -ENOBUFS;
	sk = (struct vxvdex_sock *) sk_alloc(net, PF_VXVDEX, GFP_KERNEL, &vxvdex_proto, kern);
	if (sk == NULL)
		goto out;
	sock->ops = &vxvdex_ops;
	sock_init_data(sock, (struct sock *) sk);

	err = sock_create_kern(&init_net, protocol, SOCK_DGRAM, IPPROTO_UDP, &sk->lower_sock);
	if (err) {
		sk_common_release((struct sock *) sk);
		goto out;
	}
	sk->vxhdr = vid2uint64(egid.val);
	if (likely(sk->lower_sock->sk)) {
		//sk->lower_sock->sk->sk_rcvbuf = rcvbuf;
		if (protocol == AF_INET) {
			struct inet_sock *inet = inet_sk(sk->lower_sock->sk);
			if (likely(inet)) {
				inet->uc_ttl = inet->mc_ttl = check_ttl(maxttl);
				inet->mc_all = 0;
				if (ifindex > 0)
					inet->uc_index = inet->mc_index = ifindex;
			}
		} else { //AF_INET6
			struct ipv6_pinfo *np = inet6_sk(sk->lower_sock->sk);
			if (likely(np)) {
				np->hop_limit =  np->mcast_hops = check_ttl(maxttl);
				if (ifindex > 0)
					np->ucast_oif = np->mcast_oif = ifindex;
			}
		}
	}

out:
	return err;
}

/* MAIN SECTION */
/* Module constructor/destructor */
static struct net_proto_family vxvdex_family_ops = {
	.family = PF_VXVDEX,
	.create = vxvdex_create,
	.owner  = THIS_MODULE,
};

/* VXVDEX constructor */
static int vxvdex_init(void)
{
	if (proto_register(&vxvdex_proto, 1) != 0)
		return -1;
	sock_register(&vxvdex_family_ops);
	printk(KERN_INFO "VXVDEX: Virtual Square Project, University of Bologna 2016\n");
	return 0;
}

/* VXVDEX destructor */
static void vxvdex_exit(void)
{
	sock_unregister(PF_VXVDEX);
	proto_unregister(&vxvdex_proto);
	printk(KERN_INFO "VXVDEX removed\n");
}

module_init(vxvdex_init);
module_exit(vxvdex_exit);
