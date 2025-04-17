// SPDX-License-Identifier: GPL-2.0-only
/*
 * HWSIM IEEE 802.15.4 interface
 *
 * (C) 2018 Mojatau, Alexander Aring <aring@mojatau.com>
 * Copyright 2007-2012 Siemens AG
 *
 * Based on fakelb, original Written by:
 * Sergey Lapin <slapin@ossfans.org>
 * Dmitry Eremin-Solenikov <dbaryshkov@gmail.com>
 * Alexander Smirnov <alex.bluesman.smirnov@gmail.com>
 */

#include <linux/module.h>
#include <linux/timer.h>
#include <linux/platform_device.h>
#include <linux/debugfs.h>
#include <linux/rtnetlink.h>
#include <linux/netdevice.h>
#include <linux/device.h>
#include <linux/spinlock.h>
#include <net/ieee802154_netdev.h>
#include <net/mac802154.h>
#include <net/cfg802154.h>
#include <net/genetlink.h>
#include <net/netns/generic.h>
#include <linux/rhashtable.h>
#include "mac802154_hwsim.h"
#include <linux/virtio.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_config.h>

#define WARN_QUEUE 100
#define MAX_QUEUE 200
#define HWSIM_SKB_CB(__skb) ((struct hwsim_cb *)&((__skb)->cb[0]))
#define IEEE802154_FCF_FRAME_TYPE_MASK 0x0007
#define IEEE802154_FRAME_TYPE_DATA     0x0001

MODULE_DESCRIPTION("Software simulator of IEEE 802.15.4 radio(s) for mac802154");
MODULE_LICENSE("GPL");

static int radios = 2;
module_param(radios, int, 0444);
MODULE_PARM_DESC(radios, "Number of simulated radios");

static LIST_HEAD(hwsim_phys);
static DEFINE_MUTEX(hwsim_phys_lock);
static int hwsim_radios_generation = 1;

static struct platform_device *mac802154hwsim_dev;

/* MAC802154_HWSIM netlink family */
static struct genl_family hwsim_genl_family;

static int hwsim_radio_idx;

static unsigned int hwsim_net_id;

static DEFINE_IDA(hwsim_netgroup_ida);

static struct class *hwsim_class;

struct hwsim_net {
	int netgroup;
	u32 wmediumd;
};

struct hwsim_cb {
	uintptr_t cookie;
};

static inline u32 hwsim_net_get_wmediumd(struct net *net)
{
	struct hwsim_net *hwsim_net = net_generic(net, hwsim_net_id);

	return hwsim_net->wmediumd;
}

static inline void hwsim_net_set_wmediumd(struct net *net, u32 portid)
{
	struct hwsim_net *hwsim_net = net_generic(net, hwsim_net_id);

	hwsim_net->wmediumd = portid;
}

static inline int hwsim_net_get_netgroup(struct net *net)
{
	struct hwsim_net *hwsim_net = net_generic(net, hwsim_net_id);

	return hwsim_net->netgroup;
}

static inline int hwsim_net_set_netgroup(struct net *net)
{
	struct hwsim_net *hwsim_net = net_generic(net, hwsim_net_id);

	hwsim_net->netgroup = ida_alloc(&hwsim_netgroup_ida, GFP_KERNEL);
	return hwsim_net->netgroup >= 0 ? 0 : -ENOMEM;
}

#if IS_REACHABLE(CONFIG_VIRTIO)

/* MAC80211_HWSIM virtio queues */
static struct virtqueue *hwsim_vqs[HWSIM_NUM_VQS];
static bool hwsim_virtio_enabled;
static DEFINE_SPINLOCK(hwsim_virtio_lock);

static void hwsim_virtio_rx_work(struct work_struct *work);
static DECLARE_WORK(hwsim_virtio_rx, hwsim_virtio_rx_work);

static int hwsim_tx_virtio(struct hwsim_phy *phy,
			   struct sk_buff *skb)
{
	struct scatterlist sg[1];
	unsigned long flags;
	int err;

	spin_lock_irqsave(&hwsim_virtio_lock, flags);
	if (!hwsim_virtio_enabled) {
		err = -ENODEV;
		goto out_free;
	}

	sg_init_one(sg, skb->head, skb_end_offset(skb));
	err = virtqueue_add_outbuf(hwsim_vqs[HWSIM_VQ_TX], sg, 1, skb,
				   GFP_ATOMIC);
	if (err)
		goto out_free;
	virtqueue_kick(hwsim_vqs[HWSIM_VQ_TX]);
	spin_unlock_irqrestore(&hwsim_virtio_lock, flags);
	return 0;

out_free:
	spin_unlock_irqrestore(&hwsim_virtio_lock, flags);
	nlmsg_free(skb);
	return err;
}
#else
/* cause a linker error if this ends up being needed */
extern int hwsim_tx_virtio(struct hwsim_phy *phy,
			   struct sk_buff *skb);
#define hwsim_virtio_enabled false
#endif

enum hwsim_multicast_groups {
	HWSIM_MCGRP_CONFIG,
};

static const struct genl_multicast_group hwsim_mcgrps[] = {
	[HWSIM_MCGRP_CONFIG] = { .name = "config", },
};

struct hwsim_pib {
	u8 page;
	u8 channel;
	struct ieee802154_hw_addr_filt filt;
	enum ieee802154_filtering_level filt_level;

	struct rcu_head rcu;
};

struct hwsim_edge_info {
	u8 lqi;

	struct rcu_head rcu;
};

struct hwsim_edge {
	struct hwsim_phy *endpoint;
	struct hwsim_edge_info __rcu *info;

	struct list_head list;
	struct rcu_head rcu;
};

struct hwsim_phy {
	struct ieee802154_hw *hw;
	u32 idx;

	struct hwsim_pib __rcu *pib;
	bool rht_inserted;
	u8 ieee_addr[8];

	struct rhash_head rht;
	struct dentry *debugfs;
	atomic_t pending_cookie;
	struct sk_buff_head pending;
	struct device *dev;
	struct mutex mutex;

	/* Stats */
	u64 tx_pkts;
	u64 rx_pkts;
	u64 tx_bytes;
	u64 rx_bytes;
	u64 tx_dropped;
	u64 tx_failed;

	bool destroy_on_close;
	u32 portid;

	bool suspended;
	struct list_head edges;

	struct list_head list;

	/* group shared by radios created in the same netns */
	int netgroup;
	/* wmediumd portid responsible for netgroup of this radio */
	u32 wmediumd;
};

static const struct rhashtable_params hwsim_rht_params = {
	.nelem_hint = 2,
	.automatic_shrinking = true,
	.key_len = 8, //ETH_ALEN
	.key_offset = offsetof(struct hwsim_phy, ieee_addr),
	.head_offset = offsetof(struct hwsim_phy, rht),
};

static DEFINE_SPINLOCK(hwsim_radio_lock);
static struct rhashtable hwsim_radios_rht;

static int hwsim_add_one(struct genl_info *info, struct device *dev,
			 bool init);
static void hwsim_del(struct hwsim_phy *phy);

static int hwsim_hw_ed(struct ieee802154_hw *hw, u8 *level)
{
	*level = 0xbe;

	return 0;
}

static void hwsim_mcast_config_msg(struct sk_buff *mcast_skb,
				   struct genl_info *info)
{
	if (info)
		genl_notify(&hwsim_genl_family, mcast_skb, info,
			    HWSIM_MCGRP_CONFIG, GFP_KERNEL);
	else
		genlmsg_multicast(&hwsim_genl_family, mcast_skb, 0,
				  HWSIM_MCGRP_CONFIG, GFP_KERNEL);
}

static int hwsim_update_pib(struct ieee802154_hw *hw, u8 page, u8 channel,
			    struct ieee802154_hw_addr_filt *filt,
			    enum ieee802154_filtering_level filt_level)
{
	struct hwsim_phy *phy = hw->priv;
	struct hwsim_pib *pib, *pib_old;

	pib = kzalloc(sizeof(*pib), GFP_ATOMIC);
	if (!pib)
		return -ENOMEM;

	pib_old = rtnl_dereference(phy->pib);	

	pib->page = page;
	pib->channel = channel;
	pib->filt.short_addr = filt->short_addr;
	pib->filt.pan_id = filt->pan_id;
	pib->filt.ieee_addr = filt->ieee_addr;
	pib->filt.pan_coord = filt->pan_coord;
	pib->filt_level = filt_level;

	rcu_assign_pointer(phy->pib, pib);
	kfree_rcu(pib_old, rcu);

	return 0;
}

static struct hwsim_phy *get_hwsim_data_ref_from_addr(const u8 *addr)
{
	return rhashtable_lookup_fast(&hwsim_radios_rht, addr, hwsim_rht_params);
}

static int hwsim_hw_channel(struct ieee802154_hw *hw, u8 page, u8 channel)
{
	struct hwsim_phy *phy = hw->priv;
	struct hwsim_pib *pib;
	int ret;

	rcu_read_lock();
	pib = rcu_dereference(phy->pib);
	ret = hwsim_update_pib(hw, page, channel, &pib->filt, pib->filt_level);
	rcu_read_unlock();

	return ret;
}

static int hwsim_hw_addr_filt(struct ieee802154_hw *hw,
			      struct ieee802154_hw_addr_filt *filt,
			      unsigned long changed)
{
	struct hwsim_phy *phy = hw->priv;
	struct hwsim_pib *pib;
	int ret;

	rcu_read_lock();
	pib = rcu_dereference(phy->pib);
	ret = hwsim_update_pib(hw, pib->page, pib->channel, filt, pib->filt_level);
	rcu_read_unlock();

	return ret;
}

static int hwsim_unicast_netgroup(struct hwsim_phy *data,
				  struct sk_buff *skb, int portid)
{
	struct net *net;
	bool found = false;
	int res = -ENOENT;

	rcu_read_lock();
	for_each_net_rcu(net) {
		if (data->netgroup == hwsim_net_get_netgroup(net)) {
			res = genlmsg_unicast(net, skb, portid);
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	if (!found)
		nlmsg_free(skb);

	return res;
}

struct hwsim_phy *find_phy_by_link_addrs(const u8 *src_addr, const u8 *dst_addr)
{
	struct hwsim_phy *phy;

	rcu_read_lock();
	list_for_each_entry_rcu(phy, &hwsim_phys, list) {
		if (memcmp(phy->ieee_addr, src_addr, 8) == 0 ||
		    memcmp(phy->ieee_addr, dst_addr, 8) == 0) {
			rcu_read_unlock();
			return phy;
		}
	}
	rcu_read_unlock();
	return NULL;
}

bool is_mgmt_154(uint16_t fcf)
{
	uint8_t type = fcf & 0x7;
	return type == 0b000 || type == 0b011; // beacon or MAC command
}


static void mac802154_hwsim_tx_frame_nl(struct ieee802154_hw *hw, struct sk_buff *my_skb,
			     int dst_portid, u8 lqi)
{
	struct sk_buff *skb;
	struct hwsim_phy *phy = hw->priv;
	//struct hwsim_pib *pib;
	//struct ieee802154_hdr hdr;
	void *msg_head;
	unsigned int hwsim_flags = 0;
	uintptr_t cookie;
	
	/* If the queue contains MAX_QUEUE skb's drop some */
	if (skb_queue_len(&phy->pending) >= MAX_QUEUE) {
		/* Dropping until WARN_QUEUE level */
		while (skb_queue_len(&phy->pending) >= WARN_QUEUE) {
			//ieee80211_free_txskb(hw, skb_dequeue(&data->pending));
			//phy->tx_dropped++;
		}
	}

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_ATOMIC);

	if (skb == NULL)
		goto nla_put_failure;

	msg_head = genlmsg_put(skb, 0, 0, &hwsim_genl_family, 0,
			       MAC802154_HWSIM_CMD_FRAME);
	if (msg_head == NULL) {
		pr_debug("mac802154_hwsim: problem with msg_head\n");
		goto nla_put_failure;
	}

	u8 addr_buf[8];
	put_unaligned_le64(hw->phy->perm_extended_addr, addr_buf);
	put_unaligned_le64(hw->phy->perm_extended_addr, phy->ieee_addr);
	if (nla_put(skb, MAC802154_HWSIM_ATTR_ADDR_TRANSMITTER,
		    8, addr_buf))
		goto nla_put_failure;
	//verificar o 8 acima

	/* We get the skb->data */
	if (nla_put(skb, MAC802154_HWSIM_ATTR_FRAME, my_skb->len, my_skb->data))
		goto nla_put_failure;

	/* We get the flags for this transmission, and we translate them to
	   wmediumd flags  */

	//if (info->flags & IEEE80211_TX_CTL_REQ_TX_STATUS)
	//	hwsim_flags |= HWSIM_TX_CTL_REQ_TX_STATUS;

	//if (info->flags & IEEE80211_TX_CTL_NO_ACK)
	//	hwsim_flags |= HWSIM_TX_CTL_NO_ACK;

	if (nla_put_u32(skb, MAC802154_HWSIM_ATTR_FLAGS, hwsim_flags))
		goto nla_put_failure;

	/* We create a cookie to identify this skb */
	cookie = atomic_inc_return(&phy->pending_cookie);
	//info->rate_driver_data[0] = (void *)cookie;
	if (nla_put_u64_64bit(skb, MAC802154_HWSIM_ATTR_COOKIE, cookie, MAC802154_HWSIM_ATTR_PAD))
		goto nla_put_failure;

	genlmsg_end(skb, msg_head);

	if (hwsim_virtio_enabled) {
		//if (hwsim_tx_virtio(phy, skb))
		//	goto err_free_txskb;
	} else {
		if (hwsim_unicast_netgroup(phy, skb, dst_portid))
			goto err_free_txskb;
	}


	//memset(my_skb->cb, 0, sizeof(my_skb->cb));
	//HWSIM_SKB_CB(my_skb)->cookie = cookie;

	/* Enqueue the packet */
	skb_queue_tail(&phy->pending, my_skb);
	//data->tx_pkts++;
	//data->tx_bytes += my_skb->len;

	//ieee802154_rx_irqsafe(hw, skb, lqi);

	//print_hex_dump(KERN_INFO, "Frame: ", DUMP_PREFIX_OFFSET, 16, 1, skb->data, skb->len, true);
	//print_hex_dump(KERN_INFO, "Atributo FRAME: ", DUMP_PREFIX_OFFSET, 16, 1, my_skb->data, my_skb->len, true);

	return;

drop:
	//rcu_read_unlock();
	kfree_skb(skb);
nla_put_failure:
	nlmsg_free(skb);
err_free_txskb:
	pr_debug("mac802154_hwsim: error occurred in %s\n", __func__);
	//ieee80211_free_txskb(hw, my_skb);
	//data->tx_failed++;
}

static void hwsim_hw_receive(struct ieee802154_hw *hw, struct sk_buff *skb,
			     u8 lqi)
{
	struct ieee802154_hdr hdr;
	struct hwsim_phy *phy = hw->priv;
	struct hwsim_pib *pib;

	rcu_read_lock();
	pib = rcu_dereference(phy->pib);

	if (!pskb_may_pull(skb, 3)) {
		dev_dbg(hw->parent, "invalid frame\n");
		goto drop;
	}
			
	memcpy(&hdr, skb->data, 3);

	/* Level 4 filtering: Frame fields validity */
	if (pib->filt_level == IEEE802154_FILTERING_4_FRAME_FIELDS) {
		/* a) Drop reserved frame types */
		switch (mac_cb(skb)->type) {
		case IEEE802154_FC_TYPE_BEACON:
		case IEEE802154_FC_TYPE_DATA:
		case IEEE802154_FC_TYPE_ACK:
		case IEEE802154_FC_TYPE_MAC_CMD:
			break;
		default:
			dev_dbg(hw->parent, "unrecognized frame type 0x%x\n",
				mac_cb(skb)->type);
			goto drop;
		}

		/* b) Drop reserved frame versions */
		switch (hdr.fc.version) {
		case IEEE802154_2003_STD:
		case IEEE802154_2006_STD:
		case IEEE802154_STD:
			break;
		default:
			dev_dbg(hw->parent,
				"unrecognized frame version 0x%x\n",
				hdr.fc.version);
			goto drop;
		}

		/* c) PAN ID constraints */
		if ((mac_cb(skb)->dest.mode == IEEE802154_ADDR_LONG ||
		     mac_cb(skb)->dest.mode == IEEE802154_ADDR_SHORT) &&
		    mac_cb(skb)->dest.pan_id != pib->filt.pan_id &&
		    mac_cb(skb)->dest.pan_id != cpu_to_le16(IEEE802154_PANID_BROADCAST)) {
			dev_dbg(hw->parent,
				"unrecognized PAN ID %04x\n",
				le16_to_cpu(mac_cb(skb)->dest.pan_id));
			goto drop;
		}

		/* d1) Short address constraints */
		if (mac_cb(skb)->dest.mode == IEEE802154_ADDR_SHORT &&
		    mac_cb(skb)->dest.short_addr != pib->filt.short_addr &&
		    mac_cb(skb)->dest.short_addr != cpu_to_le16(IEEE802154_ADDR_BROADCAST)) {
			dev_dbg(hw->parent,
				"unrecognized short address %04x\n",
				le16_to_cpu(mac_cb(skb)->dest.short_addr));
			goto drop;
		}

		/* d2) Extended address constraints */
		if (mac_cb(skb)->dest.mode == IEEE802154_ADDR_LONG &&
		    mac_cb(skb)->dest.extended_addr != pib->filt.ieee_addr) {
			dev_dbg(hw->parent,
				"unrecognized long address 0x%016llx\n",
				mac_cb(skb)->dest.extended_addr);
			goto drop;
		}

		/* d4) Specific PAN coordinator case (no parent) */
		if ((mac_cb(skb)->type == IEEE802154_FC_TYPE_DATA ||
		     mac_cb(skb)->type == IEEE802154_FC_TYPE_MAC_CMD) &&
		    mac_cb(skb)->dest.mode == IEEE802154_ADDR_NONE) {
			dev_dbg(hw->parent,
				"relaying is not supported\n");
			goto drop;
		}

		/* e) Beacon frames follow specific PAN ID rules */
		if (mac_cb(skb)->type == IEEE802154_FC_TYPE_BEACON &&
		    pib->filt.pan_id != cpu_to_le16(IEEE802154_PANID_BROADCAST) &&
		    mac_cb(skb)->dest.pan_id != pib->filt.pan_id) {
			dev_dbg(hw->parent,
				"invalid beacon PAN ID %04x\n",
				le16_to_cpu(mac_cb(skb)->dest.pan_id));
			goto drop;
		}
	}


	rcu_read_unlock();

	ieee802154_rx_irqsafe(hw, skb, lqi);


	return;

drop:
	rcu_read_unlock();
	kfree_skb(skb);
}

static int hwsim_hw_xmit(struct ieee802154_hw *hw, struct sk_buff *skb)
{
	struct hwsim_phy *current_phy = hw->priv;
	struct hwsim_pib *current_pib, *endpoint_pib;
	struct hwsim_edge_info *einfo;
	struct hwsim_edge *e;
	u32 _portid;

	WARN_ON(current_phy->suspended);

	/* wmediumd mode check */
	_portid = READ_ONCE(current_phy->wmediumd);

	if (_portid || hwsim_virtio_enabled){
		struct sk_buff *newskb = pskb_copy(skb, GFP_ATOMIC);
		mac802154_hwsim_tx_frame_nl(hw, newskb, _portid, 255);
		//consume_skb(skb);
		dev_kfree_skb_irq(skb);
		dev_kfree_skb_irq(newskb);
	}
	else{
		rcu_read_lock();
		current_pib = rcu_dereference(current_phy->pib);
		list_for_each_entry_rcu(e, &current_phy->edges, list) {
			/* Can be changed later in rx_irqsafe, but this is only a
			* performance tweak. Received radio should drop the frame
			* in mac802154 stack anyway... so we don't need to be
			* 100% of locking here to check on suspended
			*/
			if (e->endpoint->suspended)
				continue;

			endpoint_pib = rcu_dereference(e->endpoint->pib);
			if (current_pib->page == endpoint_pib->page &&
				current_pib->channel == endpoint_pib->channel) {
				struct sk_buff *newskb = pskb_copy(skb, GFP_ATOMIC);

				einfo = rcu_dereference(e->info);
				if (newskb)
					hwsim_hw_receive(e->endpoint->hw, newskb, einfo->lqi);
			}
		}
		rcu_read_unlock();	
		ieee802154_xmit_complete(hw, skb, false);
	}
	//print_hex_dump(KERN_INFO, "Frame WMED----IUMD: ", DUMP_PREFIX_OFFSET, 16, 1, skb->data, skb->len, true);

	return 0;
}

static void mac802154_hwsim_rx(struct hwsim_phy *data,
			      //struct ieee802154_rx_info *rx_status,
			      struct sk_buff *skb)
{
	struct ieee802154_hdr *hdr = (void *)skb->data;
	//const u8 *src = hdr->source.extended_addr;
	//const u8 *dst = hdr->dest.extended_addr;
	u8 lqi = 10;

	/*if ( q(is_mgmt_154(hdr->frame_control) ||
	     ieee802154_is_data(hdr->frame_control))) {
		unsigned int link_id;

		rcu_read_lock();
		struct hwsim_phy *peer = find_phy_by_link_addrs(src, dst);
		if (peer) {
			/*struct hwsim_sta_priv *sp = (void *)sta->drv_priv;

			if (ieee80211_has_pm(hdr->frame_control))
				sp->active_links_rx &= ~BIT(link_id);
			else
				sp->active_links_rx |= BIT(link_id);

			rx_status->link_valid = true;
			rx_status->link_id = link_id;*/
		/*}
		rcu_read_unlock();
	}*/

	//struct ieee802154_rx_info *rxinfo = HWSIM_SKB_CB(skb);
	//rxinfo->lqi = lqi;
	//rxinfo->crc = 1;

	print_hex_dump(KERN_INFO, "Frame WMEDIUMD: ", DUMP_PREFIX_OFFSET, 16, 1, skb->data, skb->len, true);

	data->rx_pkts++;
	data->rx_bytes += skb->len;
	//ieee802154_rx_irqsafe(data->hw, skb, lqi);
	//hwsim_hw_receive(data->hw, skb, lqi);

	struct hwsim_phy *current_phy = data->hw->priv;
	struct hwsim_pib *current_pib, *endpoint_pib;
	struct hwsim_edge_info *einfo;
	struct hwsim_edge *e;

	WARN_ON(current_phy->suspended);

	rcu_read_lock();
	//if (!current_phy->pib) {
	//	printk("current_phy->pib é NULL\n");
	//}

	current_pib = rcu_dereference(current_phy->pib);
	list_for_each_entry_rcu(e, &current_phy->edges, list) {
		/* Can be changed later in rx_irqsafe, but this is only a
		* performance tweak. Received radio should drop the frame
		* in mac802154 stack anyway... so we don't need to be
		* 100% of locking here to check on suspended
		*/
		if (e->endpoint->suspended)
			continue;

		endpoint_pib = rcu_dereference(e->endpoint->pib);
		if (current_pib->page == endpoint_pib->page &&
			current_pib->channel == endpoint_pib->channel) {
			struct sk_buff *newskb = pskb_copy(skb, GFP_ATOMIC);
			einfo = rcu_dereference(e->info);
			
			if (newskb)
				//ieee802154_rx_irqsafe(e->endpoint->hw, newskb, einfo->lqi);
				hwsim_hw_receive(e->endpoint->hw, newskb, einfo->lqi);
		}
	}
	rcu_read_unlock();

	ieee802154_xmit_complete(data->hw, skb, false);
}

static int hwsim_cloned_frame_received_nl(struct sk_buff *skb_2,
					  struct genl_info *info)
{
	struct hwsim_phy *data2;
	//struct ieee802154_hdr *hdr;
	const u8 *dst;
	int frame_data_len;
	void *frame_data;
	struct sk_buff *skb = NULL;
	u8 lqi = 10;

	printk("nnnnnnnnnnnnn\n");

	if (!info->attrs[MAC802154_HWSIM_ATTR_ADDR_RECEIVER] ||
	    !info->attrs[MAC802154_HWSIM_ATTR_FRAME])
		goto out;

	dst = (void *)nla_data(info->attrs[MAC802154_HWSIM_ATTR_ADDR_RECEIVER]);
	frame_data_len = nla_len(info->attrs[MAC802154_HWSIM_ATTR_FRAME]);
	frame_data = (void *)nla_data(info->attrs[MAC802154_HWSIM_ATTR_FRAME]);
	
	if (frame_data_len < IEEE802154_MIN_HDR_LEN ||
    	frame_data_len > IEEE802154_MAX_FRAME_LEN)
    	goto err;
	
	/* Allocate new skb here */
	skb = alloc_skb(frame_data_len, GFP_KERNEL);
	if (skb == NULL)
		goto err;

	/* Copy the data */
	skb_put_data(skb, frame_data, frame_data_len);

	data2 = get_hwsim_data_ref_from_addr(dst);
	if (!data2)
		goto out;
	struct ieee802154_hw *hw = data2->hw;
	
	/*if (data2->use_chanctx) {
		if (data2->tmp_chan)
			channel = data2->tmp_chan;
	} else {
		channel = data2->channel;
	}*/

	if (!hwsim_virtio_enabled) {
		if (hwsim_net_get_netgroup(genl_info_net(info)) !=
		    data2->netgroup)
			goto out;

		if (info->snd_portid != data2->wmediumd)
			goto out;
	}

	//print_hex_dump(KERN_INFO, "Frame: ", DUMP_PREFIX_OFFSET, 16, 1, skb_2->data, skb_2->len, true);

	/* check if radio is configured properly */

	//if ((data2->idle && !data2->tmp_chan) || !data2->started)
	//	goto out;

	/* A frame is received from user space */
	//memset(&rx_status, 0, sizeof(rx_status));
	/*if (info->attrs[HWSIM_ATTR_FREQ]) {
		struct tx_iter_data iter_data = {};

		/* throw away off-channel packets, but allow both the temporary
		 * ("hw" scan/remain-on-channel), regular channels and links,
		 * since the internal datapath also allows this
		 */
	/*	rx_status.freq = nla_get_u32(info->attrs[HWSIM_ATTR_FREQ]);

		iter_data.channel = ieee80211_get_channel(data2->hw->wiphy,
							  rx_status.freq);
		if (!iter_data.channel)
			goto out;
		rx_status.band = iter_data.channel->band;

		mutex_lock(&data2->mutex);
		if (!hwsim_chans_compat(iter_data.channel, channel)) {
			ieee80211_iterate_active_interfaces_atomic(
				data2->hw, IEEE80211_IFACE_ITER_NORMAL,
				mac80211_hwsim_tx_iter, &iter_data);
			if (!iter_data.receive) {
				mutex_unlock(&data2->mutex);
				goto out;
			}
		}
		mutex_unlock(&data2->mutex);
	} else if (!channel) {
		goto out;
	} else {
		rx_status.freq = channel->center_freq;
		rx_status.band = channel->band;
	}

	rx_status.rate_idx = nla_get_u32(info->attrs[HWSIM_ATTR_RX_RATE]);
	if (rx_status.rate_idx >= data2->hw->wiphy->bands[rx_status.band]->n_bitrates)
		goto out;
	rx_status.signal = nla_get_u32(info->attrs[HWSIM_ATTR_SIGNAL]);

	hdr = (void *)skb->data;

	if (ieee80211_is_beacon(hdr->frame_control) ||
	    ieee80211_is_probe_resp(hdr->frame_control))
		rx_status.boottime_ns = ktime_get_boottime_ns();

	mac80211_hwsim_rx(data2, &rx_status, skb);
	*/
  //  ieee802154_rx_irqsafe(data2->hw, skb, lqi);
	//ieee802154_xmit_complete(data2->hw, skb, false);

	mac802154_hwsim_rx(data2, skb);
	return 0;
err:
	pr_debug("mac802154_hwsim: error occurred in %s\n", __func__);
out:
	dev_kfree_skb(skb);
	return -EINVAL;
}

static int hwsim_hw_start(struct ieee802154_hw *hw)
{
	struct hwsim_phy *phy = hw->priv;

	phy->suspended = false;

	return 0;
}

static void hwsim_hw_stop(struct ieee802154_hw *hw)
{
	struct hwsim_phy *phy = hw->priv;

	phy->suspended = true;
}

static int
hwsim_set_promiscuous_mode(struct ieee802154_hw *hw, const bool on)
{
	enum ieee802154_filtering_level filt_level;
	struct hwsim_phy *phy = hw->priv;
	struct hwsim_pib *pib;
	int ret;

	if (on)
		filt_level = IEEE802154_FILTERING_NONE;
	else
		filt_level = IEEE802154_FILTERING_4_FRAME_FIELDS;

	rcu_read_lock();
	pib = rcu_dereference(phy->pib);
	ret = hwsim_update_pib(hw, pib->page, pib->channel, &pib->filt, filt_level);
	rcu_read_unlock();

	return ret;
}

static const struct ieee802154_ops hwsim_ops = {
	.owner = THIS_MODULE,
	.xmit_async = hwsim_hw_xmit,
	.ed = hwsim_hw_ed,
	.set_channel = hwsim_hw_channel,
	.start = hwsim_hw_start,
	.stop = hwsim_hw_stop,
	.set_promiscuous_mode = hwsim_set_promiscuous_mode,
	.set_hw_addr_filt = hwsim_hw_addr_filt,
};

static int hwsim_new_radio_nl(struct sk_buff *msg, struct genl_info *info)
{
	return hwsim_add_one(info, &mac802154hwsim_dev->dev, false);
}

static void hwsim_mcast_del_radio(int id, const char *hwname,
				  struct genl_info *info)
{
	struct sk_buff *skb;
	void *data;
	int ret;

	skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!skb)
		return;

	data = genlmsg_put(skb, 0, 0, &hwsim_genl_family, 0,
			   MAC802154_HWSIM_CMD_DEL_RADIO);
	if (!data)
		goto error;

	ret = nla_put_u32(skb, MAC802154_HWSIM_ATTR_RADIO_ID, id);
	if (ret < 0)
		goto error;

	//ret = nla_put(skb, HWSIM_ATTR_RADIO_NAME, strlen(hwname),
	//	      hwname);
	//if (ret < 0)
	//	goto error;

	genlmsg_end(skb, data);

	hwsim_mcast_config_msg(skb, info);

	return;

error:
	nlmsg_free(skb);
}

static int hwsim_del_radio_nl(struct sk_buff *msg, struct genl_info *info)
{
	struct hwsim_phy *phy, *tmp;
	s64 idx = -1;

	if (!info->attrs[MAC802154_HWSIM_ATTR_RADIO_ID])
		return -EINVAL;

	idx = nla_get_u32(info->attrs[MAC802154_HWSIM_ATTR_RADIO_ID]);

	mutex_lock(&hwsim_phys_lock);
	list_for_each_entry_safe(phy, tmp, &hwsim_phys, list) {
		if (idx == phy->idx) {
			hwsim_del(phy);
			mutex_unlock(&hwsim_phys_lock);
			return 0;
		}
	}
	mutex_unlock(&hwsim_phys_lock);

	return -ENODEV;
}

static void hwsim_del_radio(struct hwsim_phy *data,
				     const char *hwname,
				     struct genl_info *info)
{
	hwsim_mcast_del_radio(data->idx, hwname, info);
	debugfs_remove_recursive(data->debugfs);
	ieee802154_unregister_hw(data->hw);
	device_release_driver(data->dev);
	device_unregister(data->dev);
	ieee802154_free_hw(data->hw);
}


static int append_radio_msg(struct sk_buff *skb, struct hwsim_phy *phy)
{
	struct nlattr *nl_edges, *nl_edge;
	struct hwsim_edge_info *einfo;
	struct hwsim_edge *e;
	int ret;

	ret = nla_put_u32(skb, MAC802154_HWSIM_ATTR_RADIO_ID, phy->idx);
	if (ret < 0)
		return ret;

	rcu_read_lock();
	if (list_empty(&phy->edges)) {
		rcu_read_unlock();
		return 0;
	}

	nl_edges = nla_nest_start_noflag(skb,
					 MAC802154_HWSIM_ATTR_RADIO_EDGES);
	if (!nl_edges) {
		rcu_read_unlock();
		return -ENOBUFS;
	}

	list_for_each_entry_rcu(e, &phy->edges, list) {
		nl_edge = nla_nest_start_noflag(skb,
						MAC802154_HWSIM_ATTR_RADIO_EDGE);
		if (!nl_edge) {
			rcu_read_unlock();
			nla_nest_cancel(skb, nl_edges);
			return -ENOBUFS;
		}

		ret = nla_put_u32(skb, MAC802154_HWSIM_EDGE_ATTR_ENDPOINT_ID,
				  e->endpoint->idx);
		if (ret < 0) {
			rcu_read_unlock();
			nla_nest_cancel(skb, nl_edge);
			nla_nest_cancel(skb, nl_edges);
			return ret;
		}

		einfo = rcu_dereference(e->info);
		ret = nla_put_u8(skb, MAC802154_HWSIM_EDGE_ATTR_LQI,
				 einfo->lqi);
		if (ret < 0) {
			rcu_read_unlock();
			nla_nest_cancel(skb, nl_edge);
			nla_nest_cancel(skb, nl_edges);
			return ret;
		}

		nla_nest_end(skb, nl_edge);
	}
	rcu_read_unlock();

	nla_nest_end(skb, nl_edges);

	return 0;
}

static int hwsim_get_radio(struct sk_buff *skb, struct hwsim_phy *phy,
			   u32 portid, u32 seq,
			   struct netlink_callback *cb, int flags)
{
	void *hdr;
	int res;

	hdr = genlmsg_put(skb, portid, seq, &hwsim_genl_family, flags,
			  MAC802154_HWSIM_CMD_GET_RADIO);
	if (!hdr)
		return -EMSGSIZE;

	if (cb)
		genl_dump_check_consistent(cb, hdr);

	res = append_radio_msg(skb, phy);
	if (res < 0)
		goto out_err;

	genlmsg_end(skb, hdr);
	return 0;

out_err:
	genlmsg_cancel(skb, hdr);
	return res;
}

static int hwsim_get_radio_nl(struct sk_buff *msg, struct genl_info *info)
{
	struct hwsim_phy *phy;
	struct sk_buff *skb;
	int idx, res = -ENODEV;


	if (!info->attrs[MAC802154_HWSIM_ATTR_RADIO_ID])
		return -EINVAL;
	idx = nla_get_u32(info->attrs[MAC802154_HWSIM_ATTR_RADIO_ID]);

	mutex_lock(&hwsim_phys_lock);
	list_for_each_entry(phy, &hwsim_phys, list) {
		if (phy->idx != idx)
			continue;

		skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
		if (!skb) {
			res = -ENOMEM;
			goto out_err;
		}

		res = hwsim_get_radio(skb, phy, info->snd_portid,
				      info->snd_seq, NULL, 0);
		if (res < 0) {
			nlmsg_free(skb);
			goto out_err;
		}

		res = genlmsg_reply(skb, info);
		break;
	}

out_err:
	mutex_unlock(&hwsim_phys_lock);

	return res;
}

static int hwsim_dump_radio_nl(struct sk_buff *skb,
			       struct netlink_callback *cb)
{
	int idx = cb->args[0];
	struct hwsim_phy *phy;
	int res;

	mutex_lock(&hwsim_phys_lock);

	if (idx == hwsim_radio_idx)
		goto done;

	list_for_each_entry(phy, &hwsim_phys, list) {
		if (phy->idx < idx)
			continue;

		res = hwsim_get_radio(skb, phy, NETLINK_CB(cb->skb).portid,
				      cb->nlh->nlmsg_seq, cb, NLM_F_MULTI);
		if (res < 0)
			break;

		idx = phy->idx + 1;
	}

	cb->args[0] = idx;

done:
	mutex_unlock(&hwsim_phys_lock);
	return skb->len;
}

/* caller need to held hwsim_phys_lock */
static struct hwsim_phy *hwsim_get_radio_by_id(uint32_t idx)
{
	struct hwsim_phy *phy;

	list_for_each_entry(phy, &hwsim_phys, list) {
		if (phy->idx == idx)
			return phy;
	}

	return NULL;
}

static const struct nla_policy hwsim_edge_policy[MAC802154_HWSIM_EDGE_ATTR_MAX + 1] = {
	[MAC802154_HWSIM_EDGE_ATTR_ENDPOINT_ID] = { .type = NLA_U32 },
	[MAC802154_HWSIM_EDGE_ATTR_LQI] = { .type = NLA_U8 },
};

static struct hwsim_edge *hwsim_alloc_edge(struct hwsim_phy *endpoint, u8 lqi)
{
	struct hwsim_edge_info *einfo;
	struct hwsim_edge *e;

	e = kzalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return NULL;

	einfo = kzalloc(sizeof(*einfo), GFP_KERNEL);
	if (!einfo) {
		kfree(e);
		return NULL;
	}

	einfo->lqi = 0xff;
	rcu_assign_pointer(e->info, einfo);
	e->endpoint = endpoint;

	return e;
}

static void hwsim_free_edge(struct hwsim_edge *e)
{
	struct hwsim_edge_info *einfo;

	rcu_read_lock();
	einfo = rcu_dereference(e->info);
	rcu_read_unlock();

	kfree_rcu(einfo, rcu);
	kfree_rcu(e, rcu);
}

static int hwsim_new_edge_nl(struct sk_buff *msg, struct genl_info *info)
{
	struct nlattr *edge_attrs[MAC802154_HWSIM_EDGE_ATTR_MAX + 1];
	struct hwsim_phy *phy_v0, *phy_v1;
	struct hwsim_edge *e;
	u32 v0, v1;

	if (!info->attrs[MAC802154_HWSIM_ATTR_RADIO_ID] ||
	    !info->attrs[MAC802154_HWSIM_ATTR_RADIO_EDGE])
		return -EINVAL;

	if (nla_parse_nested_deprecated(edge_attrs, MAC802154_HWSIM_EDGE_ATTR_MAX, info->attrs[MAC802154_HWSIM_ATTR_RADIO_EDGE], hwsim_edge_policy, NULL))
		return -EINVAL;

	if (!edge_attrs[MAC802154_HWSIM_EDGE_ATTR_ENDPOINT_ID])
		return -EINVAL;

	v0 = nla_get_u32(info->attrs[MAC802154_HWSIM_ATTR_RADIO_ID]);
	v1 = nla_get_u32(edge_attrs[MAC802154_HWSIM_EDGE_ATTR_ENDPOINT_ID]);

	if (v0 == v1)
		return -EINVAL;

	mutex_lock(&hwsim_phys_lock);
	phy_v0 = hwsim_get_radio_by_id(v0);
	if (!phy_v0) {
		mutex_unlock(&hwsim_phys_lock);
		return -ENOENT;
	}

	phy_v1 = hwsim_get_radio_by_id(v1);
	if (!phy_v1) {
		mutex_unlock(&hwsim_phys_lock);
		return -ENOENT;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(e, &phy_v0->edges, list) {
		if (e->endpoint->idx == v1) {
			mutex_unlock(&hwsim_phys_lock);
			rcu_read_unlock();
			return -EEXIST;
		}
	}
	rcu_read_unlock();

	e = hwsim_alloc_edge(phy_v1, 0xff);
	if (!e) {
		mutex_unlock(&hwsim_phys_lock);
		return -ENOMEM;
	}
	list_add_rcu(&e->list, &phy_v0->edges);
	/* wait until changes are done under hwsim_phys_lock lock
	 * should prevent of calling this function twice while
	 * edges list has not the changes yet.
	 */
	synchronize_rcu();
	mutex_unlock(&hwsim_phys_lock);

	return 0;
}

static int hwsim_del_edge_nl(struct sk_buff *msg, struct genl_info *info)
{
	struct nlattr *edge_attrs[MAC802154_HWSIM_EDGE_ATTR_MAX + 1];
	struct hwsim_phy *phy_v0;
	struct hwsim_edge *e;
	u32 v0, v1;

	if (!info->attrs[MAC802154_HWSIM_ATTR_RADIO_ID] ||
	    !info->attrs[MAC802154_HWSIM_ATTR_RADIO_EDGE])
		return -EINVAL;

	if (nla_parse_nested_deprecated(edge_attrs, MAC802154_HWSIM_EDGE_ATTR_MAX, info->attrs[MAC802154_HWSIM_ATTR_RADIO_EDGE], hwsim_edge_policy, NULL))
		return -EINVAL;

	if (!edge_attrs[MAC802154_HWSIM_EDGE_ATTR_ENDPOINT_ID])
		return -EINVAL;

	v0 = nla_get_u32(info->attrs[MAC802154_HWSIM_ATTR_RADIO_ID]);
	v1 = nla_get_u32(edge_attrs[MAC802154_HWSIM_EDGE_ATTR_ENDPOINT_ID]);

	mutex_lock(&hwsim_phys_lock);
	phy_v0 = hwsim_get_radio_by_id(v0);
	if (!phy_v0) {
		mutex_unlock(&hwsim_phys_lock);
		return -ENOENT;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(e, &phy_v0->edges, list) {
		if (e->endpoint->idx == v1) {
			rcu_read_unlock();
			list_del_rcu(&e->list);
			hwsim_free_edge(e);
			/* same again - wait until list changes are done */
			synchronize_rcu();
			mutex_unlock(&hwsim_phys_lock);
			return 0;
		}
	}
	rcu_read_unlock();

	mutex_unlock(&hwsim_phys_lock);

	return -ENOENT;
}

static int hwsim_set_edge_lqi(struct sk_buff *msg, struct genl_info *info)
{
	struct nlattr *edge_attrs[MAC802154_HWSIM_EDGE_ATTR_MAX + 1];
	struct hwsim_edge_info *einfo, *einfo_old;
	struct hwsim_phy *phy_v0;
	struct hwsim_edge *e;
	u32 v0, v1;
	u8 lqi;

	if (!info->attrs[MAC802154_HWSIM_ATTR_RADIO_ID] ||
	    !info->attrs[MAC802154_HWSIM_ATTR_RADIO_EDGE])
		return -EINVAL;

	if (nla_parse_nested_deprecated(edge_attrs, MAC802154_HWSIM_EDGE_ATTR_MAX, info->attrs[MAC802154_HWSIM_ATTR_RADIO_EDGE], hwsim_edge_policy, NULL))
		return -EINVAL;

	if (!edge_attrs[MAC802154_HWSIM_EDGE_ATTR_ENDPOINT_ID] ||
	    !edge_attrs[MAC802154_HWSIM_EDGE_ATTR_LQI])
		return -EINVAL;

	v0 = nla_get_u32(info->attrs[MAC802154_HWSIM_ATTR_RADIO_ID]);
	v1 = nla_get_u32(edge_attrs[MAC802154_HWSIM_EDGE_ATTR_ENDPOINT_ID]);
	lqi = nla_get_u8(edge_attrs[MAC802154_HWSIM_EDGE_ATTR_LQI]);

	mutex_lock(&hwsim_phys_lock);
	phy_v0 = hwsim_get_radio_by_id(v0);
	if (!phy_v0) {
		mutex_unlock(&hwsim_phys_lock);
		return -ENOENT;
	}

	einfo = kzalloc(sizeof(*einfo), GFP_KERNEL);
	if (!einfo) {
		mutex_unlock(&hwsim_phys_lock);
		return -ENOMEM;
	}

	rcu_read_lock();
	list_for_each_entry_rcu(e, &phy_v0->edges, list) {
		if (e->endpoint->idx == v1) {
			einfo->lqi = lqi;
			einfo_old = rcu_replace_pointer(e->info, einfo,
							lockdep_is_held(&hwsim_phys_lock));
			rcu_read_unlock();
			kfree_rcu(einfo_old, rcu);
			mutex_unlock(&hwsim_phys_lock);
			return 0;
		}
	}
	rcu_read_unlock();

	kfree(einfo);
	mutex_unlock(&hwsim_phys_lock);

	return -ENOENT;
}

static int hwsim_tx_info_frame_received_nl(struct sk_buff *skb_2,
					   struct genl_info *info)
{

	//struct ieee802154_hdr *hdr;
	struct hwsim_phy *data2;
	struct hwsim_cb *txi;
	//struct hwsim_tx_rate *tx_attempts;
	u64 ret_skb_cookie;
	struct sk_buff *skb, *tmp;
	const u8 *src;
	unsigned int hwsim_flags;
	//int i;
	unsigned long flags;
	bool found = false;
	bool acked = true;
	
	if (!info->attrs[MAC802154_HWSIM_ATTR_ADDR_TRANSMITTER] ||
	    !info->attrs[MAC802154_HWSIM_ATTR_FLAGS] ||
	    !info->attrs[MAC802154_HWSIM_ATTR_COOKIE] 
	    //!info->attrs[HWSIM_ATTR_SIGNAL] ||
	    //!info->attrs[MAC802154_HWSIM_ATTR_TX_INFO]
		)
		goto out;

	src = (void *)nla_data(info->attrs[MAC802154_HWSIM_ATTR_ADDR_TRANSMITTER]);
	hwsim_flags = nla_get_u32(info->attrs[MAC802154_HWSIM_ATTR_FLAGS]);
	ret_skb_cookie = nla_get_u64(info->attrs[MAC802154_HWSIM_ATTR_COOKIE]);

	//print_hex_dump(KERN_INFO, "Frame: ", DUMP_PREFIX_OFFSET, 16, 1, skb_2->data, skb_2->len, true);

	data2 = get_hwsim_data_ref_from_addr(src);
	if (!data2)
		goto out;
	
	if (!hwsim_virtio_enabled) {
		if (hwsim_net_get_netgroup(genl_info_net(info)) !=
		    data2->netgroup)
			goto out;

		if (info->snd_portid != data2->wmediumd)
			goto out;
	}

	/* look for the skb matching the cookie passed back from user */
	spin_lock_irqsave(&data2->pending.lock, flags);
	skb_queue_walk_safe(&data2->pending, skb, tmp) {
		uintptr_t skb_cookie = HWSIM_SKB_CB(skb)->cookie;
		if (skb_cookie == ret_skb_cookie) {
			__skb_unlink(skb, &data2->pending);
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&data2->pending.lock, flags);

	/* not found */
	if (!found)
		goto out;

	/* Tx info received because the frame was broadcasted on user space,
	 so we get all the necessary info: tx attempts and skb control buff */

	//tx_attempts = (struct hwsim_tx_rate *)nla_data(
	//	       info->attrs[MAC802154_HWSIM_ATTR_TX_INFO]);

	/* now send back TX status */
	txi = HWSIM_SKB_CB(skb);

	/*for (i = 0; i < IEEE80211_TX_MAX_RATES; i++) {
		txi->status.rates[i].idx = tx_attempts[i].idx;
		txi->status.rates[i].count = tx_attempts[i].count;
	}*/

	//txi->status.ack_signal = nla_get_u32(info->attrs[HWSIM_ATTR_SIGNAL]);

	/*if (!(hwsim_flags & HWSIM_TX_CTL_NO_ACK) &&
	   (hwsim_flags & HWSIM_TX_STAT_ACK)) {
		if (skb->len >= 16) {
			hdr = (struct ieee80211_hdr *) skb->data;
			mac80211_hwsim_monitor_ack(data2->channel,
						   hdr->addr2);
		}
		txi->flags |= IEEE80211_TX_STAT_ACK;
	}

	if (hwsim_flags & HWSIM_TX_CTL_NO_ACK)
		txi->flags |= IEEE80211_TX_STAT_NOACK_TRANSMITTED;*/

	//ieee802154_xmit_complete(data2->hw, skb, acked);

	return 0;
out:
	return -EINVAL;

}

static void hwsim_register_wmediumd(struct net *net, u32 portid)
{
	struct hwsim_phy *data;
	
	hwsim_net_set_wmediumd(net, portid);

	spin_lock_bh(&hwsim_radio_lock);
	list_for_each_entry(data, &hwsim_phys, list) {
		if (data->netgroup == hwsim_net_get_netgroup(net))
			data->wmediumd = portid;
	}
	spin_unlock_bh(&hwsim_radio_lock);
}

static int hwsim_register_received_nl(struct sk_buff *msg, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	//struct hwsim_phy *data;
	int chans = 1;
	
	//spin_lock_bh(&hwsim_radio_lock);
	//list_for_each_entry(data, &hwsim_radios, list)
	//	chans = max(chans, data->channels);
	//spin_unlock_bh(&hwsim_radio_lock);

	/* In the future we should revise the userspace API and allow it
	 * to set a flag that it does support multi-channel, then we can
	 * let this pass conditionally on the flag.
	 * For current userspace, prohibit it since it won't work right.
	 */
	
	if (chans > 1)
		return -EOPNOTSUPP;

	if (hwsim_net_get_wmediumd(net))
		return -EBUSY;

	hwsim_register_wmediumd(net, info->snd_portid);

	pr_debug("mac802154_hwsim: received a REGISTER, "
	       "switching to wmediumd mode with pid %d\n", info->snd_portid);

	return 0;
}


/* MAC802154_HWSIM netlink policy */

static const struct nla_policy hwsim_genl_policy[MAC802154_HWSIM_ATTR_MAX + 1] = {
	[MAC802154_HWSIM_ATTR_RADIO_ID] = { .type = NLA_U32 },
	[MAC802154_HWSIM_ATTR_RADIO_EDGE] = { .type = NLA_NESTED },
	[MAC802154_HWSIM_ATTR_RADIO_EDGES] = { .type = NLA_NESTED },
	[MAC802154_HWSIM_ATTR_ADDR_RECEIVER] = { .type = NLA_BINARY, .len = 8 },
	[MAC802154_HWSIM_ATTR_ADDR_TRANSMITTER] = { .type = NLA_BINARY, .len = 8 },
	[MAC802154_HWSIM_ATTR_FRAME] = { .type = NLA_BINARY,
			       .len = IEEE802154_MAX_FRAME_LEN },
};

/* Generic Netlink operations array */
static const struct genl_small_ops hwsim_nl_ops[] = {
	{
		.cmd = MAC802154_HWSIM_CMD_NEW_RADIO,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = hwsim_new_radio_nl,
		.flags = GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd = MAC802154_HWSIM_CMD_DEL_RADIO,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = hwsim_del_radio_nl,
		.flags = GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd = MAC802154_HWSIM_CMD_GET_RADIO,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = hwsim_get_radio_nl,
		.dumpit = hwsim_dump_radio_nl,
	},
	{
		.cmd = MAC802154_HWSIM_CMD_NEW_EDGE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = hwsim_new_edge_nl,
		.flags = GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd = MAC802154_HWSIM_CMD_DEL_EDGE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = hwsim_del_edge_nl,
		.flags = GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd = MAC802154_HWSIM_CMD_SET_EDGE,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = hwsim_set_edge_lqi,
		.flags = GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd = MAC802154_HWSIM_CMD_REGISTER,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = hwsim_register_received_nl,
		.flags = GENL_UNS_ADMIN_PERM,
	},
	{
		.cmd = MAC802154_HWSIM_CMD_TX_INFO_FRAME,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = hwsim_tx_info_frame_received_nl,
	},
	{
		.cmd = MAC802154_HWSIM_CMD_FRAME,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = hwsim_cloned_frame_received_nl,
	},
};

static struct genl_family hwsim_genl_family __ro_after_init = {
	.name = "MAC802154_HWSIM",
	.version = 1,
	.maxattr = MAC802154_HWSIM_ATTR_MAX,
	.policy = hwsim_genl_policy,
	.netnsok = true,
	.module = THIS_MODULE,
	.small_ops = hwsim_nl_ops,
	.n_small_ops = ARRAY_SIZE(hwsim_nl_ops),
	.resv_start_op = MAC802154_HWSIM_CMD_TX_INFO_FRAME + 1,
	.mcgrps = hwsim_mcgrps,
	.n_mcgrps = ARRAY_SIZE(hwsim_mcgrps),
};

static void hwsim_mcast_new_radio(struct genl_info *info, struct hwsim_phy *phy)
{
	struct sk_buff *mcast_skb;
	void *data;

	mcast_skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!mcast_skb)
		return;

	data = genlmsg_put(mcast_skb, 0, 0, &hwsim_genl_family, 0,
			   MAC802154_HWSIM_CMD_NEW_RADIO);
	if (!data)
		goto out_err;

	if (append_radio_msg(mcast_skb, phy) < 0)
		goto out_err;

	genlmsg_end(mcast_skb, data);

	hwsim_mcast_config_msg(mcast_skb, info);
	return;

out_err:
	genlmsg_cancel(mcast_skb, data);
	nlmsg_free(mcast_skb);
}

static void hwsim_edge_unsubscribe_me(struct hwsim_phy *phy)
{
	struct hwsim_phy *tmp;
	struct hwsim_edge *e;

	rcu_read_lock();
	/* going to all phy edges and remove phy from it */
	list_for_each_entry(tmp, &hwsim_phys, list) {
		list_for_each_entry_rcu(e, &tmp->edges, list) {
			if (e->endpoint->idx == phy->idx) {
				list_del_rcu(&e->list);
				hwsim_free_edge(e);
			}
		}
	}
	rcu_read_unlock();

	synchronize_rcu();
}

static int hwsim_subscribe_all_others(struct hwsim_phy *phy)
{
	struct hwsim_phy *sub;
	struct hwsim_edge *e;

	list_for_each_entry(sub, &hwsim_phys, list) {
		e = hwsim_alloc_edge(sub, 0xff);
		if (!e)
			goto me_fail;

		list_add_rcu(&e->list, &phy->edges);
	}

	list_for_each_entry(sub, &hwsim_phys, list) {
		e = hwsim_alloc_edge(phy, 0xff);
		if (!e)
			goto sub_fail;

		list_add_rcu(&e->list, &sub->edges);
	}

	return 0;

sub_fail:
	hwsim_edge_unsubscribe_me(phy);
me_fail:
	rcu_read_lock();
	list_for_each_entry_rcu(e, &phy->edges, list) {
		list_del_rcu(&e->list);
		hwsim_free_edge(e);
	}
	rcu_read_unlock();
	return -ENOMEM;
}

struct hwsim_new_radio_params {
	
};

static int hwsim_add_one(struct genl_info *info, struct device *dev,
			 bool init)
{
	struct ieee802154_hw *hw;
	struct hwsim_phy *phy;
	struct hwsim_pib *pib;
	struct net *net;
	int idx;
	int err;
	int ret;

	idx = hwsim_radio_idx++;

	hw = ieee802154_alloc_hw(sizeof(*phy), &hwsim_ops);
	if (!hw)
		return -ENOMEM;

	if (info)
		net = genl_info_net(info);
	else
		net = &init_net;
	wpan_phy_net_set(hw->phy, net);
	
	phy = hw->priv;
	phy->hw = hw;

	skb_queue_head_init(&phy->pending);

	/* 868 MHz BPSK	802.15.4-2003 */
	hw->phy->supported.channels[0] |= 1;
	/* 915 MHz BPSK	802.15.4-2003 */
	hw->phy->supported.channels[0] |= 0x7fe;
	/* 2.4 GHz O-QPSK 802.15.4-2003 */
	hw->phy->supported.channels[0] |= 0x7FFF800;
	/* 868 MHz ASK 802.15.4-2006 */
	hw->phy->supported.channels[1] |= 1;
	/* 915 MHz ASK 802.15.4-2006 */
	hw->phy->supported.channels[1] |= 0x7fe;
	/* 868 MHz O-QPSK 802.15.4-2006 */
	hw->phy->supported.channels[2] |= 1;
	/* 915 MHz O-QPSK 802.15.4-2006 */
	hw->phy->supported.channels[2] |= 0x7fe;
	/* 2.4 GHz CSS 802.15.4a-2007 */
	hw->phy->supported.channels[3] |= 0x3fff;
	/* UWB Sub-gigahertz 802.15.4a-2007 */
	hw->phy->supported.channels[4] |= 1;
	/* UWB Low band 802.15.4a-2007 */
	hw->phy->supported.channels[4] |= 0x1e;
	/* UWB High band 802.15.4a-2007 */
	hw->phy->supported.channels[4] |= 0xffe0;
	/* 750 MHz O-QPSK 802.15.4c-2009 */
	hw->phy->supported.channels[5] |= 0xf;
	/* 750 MHz MPSK 802.15.4c-2009 */
	hw->phy->supported.channels[5] |= 0xf0;
	/* 950 MHz BPSK 802.15.4d-2009 */
	hw->phy->supported.channels[6] |= 0x3ff;
	/* 950 MHz GFSK 802.15.4d-2009 */
	hw->phy->supported.channels[6] |= 0x3ffc00;

	hw->phy->perm_extended_addr = cpu_to_le64(((u64)0x02 << 56) | ((u64)idx));
	memcpy(phy->ieee_addr, &hw->phy->perm_extended_addr, 8);

	/* hwsim phy channel 13 as default */
	hw->phy->current_channel = 13;
	pib = kzalloc(sizeof(*pib), GFP_KERNEL);
	if (!pib) {
		err = -ENOMEM;
		goto err_pib;
	}

	if (info)
		phy->portid = info->snd_portid;

	pib->channel = 13;
	pib->filt.short_addr = cpu_to_le16(IEEE802154_ADDR_BROADCAST);
	pib->filt.pan_id = cpu_to_le16(IEEE802154_PANID_BROADCAST);
	rcu_assign_pointer(phy->pib, pib);
	phy->idx = idx;
	INIT_LIST_HEAD(&phy->edges);

	hw->flags = IEEE802154_HW_PROMISCUOUS;
	hw->parent = dev;

	phy->netgroup = hwsim_net_get_netgroup(net);
	phy->wmediumd = hwsim_net_get_wmediumd(net);

	err = ieee802154_register_hw(hw);
	if (err)
		goto err_reg;

	mutex_lock(&hwsim_phys_lock);
	if (init) {
		err = hwsim_subscribe_all_others(phy);
		if (err < 0) {
			mutex_unlock(&hwsim_phys_lock);
			goto err_subscribe;
		}
	}
	list_add_tail(&phy->list, &hwsim_phys);
	mutex_unlock(&hwsim_phys_lock);

	ret = rhashtable_insert_fast(&hwsim_radios_rht, &phy->rht, hwsim_rht_params);
	if (ret < 0) {
		pr_err("Error in adding PHY into rhashtable: %d\n", ret);
		goto failed_final_insert;
	}
	phy->rht_inserted = true;

	hwsim_mcast_new_radio(info, phy);

	return idx;

failed_final_insert:
	debugfs_remove_recursive(phy->debugfs);
	ieee802154_unregister_hw(phy->hw);
err_subscribe:
	ieee802154_unregister_hw(phy->hw);
err_reg:
	kfree(pib);
err_pib:
	ieee802154_free_hw(phy->hw);
	return err;
}

static void hwsim_del(struct hwsim_phy *phy)
{
	struct hwsim_pib *pib;
	struct hwsim_edge *e;

	hwsim_edge_unsubscribe_me(phy);

	list_del(&phy->list);

	rcu_read_lock();
	list_for_each_entry_rcu(e, &phy->edges, list) {
		list_del_rcu(&e->list);
		hwsim_free_edge(e);
	}
	pib = rcu_dereference(phy->pib);
	rcu_read_unlock();

	kfree_rcu(pib, rcu);

	ieee802154_unregister_hw(phy->hw);
	ieee802154_free_hw(phy->hw);
	class_destroy(hwsim_class);
}

static int hwsim_probe(struct platform_device *pdev)
{
	struct hwsim_phy *phy, *tmp;
	int err, i;

	for (i = 0; i < radios; i++) {
		err = hwsim_add_one(NULL, &pdev->dev, true);
		if (err < 0)
			goto err_slave;
	}

	dev_info(&pdev->dev, "Added %d mac802154 hwsim hardware radios\n", radios);
	return 0;

err_slave:
	mutex_lock(&hwsim_phys_lock);
	list_for_each_entry_safe(phy, tmp, &hwsim_phys, list)
		hwsim_del(phy);
	mutex_unlock(&hwsim_phys_lock);
	return err;
}

static void hwsim_remove(struct platform_device *pdev)
{
	struct hwsim_phy *phy, *tmp;

	mutex_lock(&hwsim_phys_lock);
	list_for_each_entry_safe(phy, tmp, &hwsim_phys, list)
		hwsim_del(phy);
	mutex_unlock(&hwsim_phys_lock);
}

static struct platform_driver mac802154hwsim_driver = {
	.probe = hwsim_probe,
	.remove = hwsim_remove,
	.driver = {
			.name = "mac802154_hwsim",
	},
};

static void remove_user_radios(u32 portid)
{
	struct hwsim_phy *entry, *tmp;
	LIST_HEAD(list);

	spin_lock_bh(&hwsim_radio_lock);
	list_for_each_entry_safe(entry, tmp, &hwsim_phys, list) {
		if (entry->destroy_on_close && entry->portid == portid) {
			list_move(&entry->list, &list);
			rhashtable_remove_fast(&hwsim_radios_rht, &entry->rht,
					       hwsim_rht_params);
			hwsim_radios_generation++;
		}
	}
	spin_unlock_bh(&hwsim_radio_lock);

	list_for_each_entry_safe(entry, tmp, &list, list) {
		list_del(&entry->list);
		hwsim_del_radio(entry, wpan_phy_name(entry->hw->phy),
					 NULL);
	}
}

static int mac802154_hwsim_netlink_notify(struct notifier_block *nb,
					 unsigned long state,
					 void *_notify)
{
	struct netlink_notify *notify = _notify;

	if (state != NETLINK_URELEASE)
		return NOTIFY_DONE;

	remove_user_radios(notify->portid);

	if (notify->portid == hwsim_net_get_wmediumd(notify->net)) {
		printk(KERN_INFO "mac802154_hwsim: wmediumd released netlink"
		       " socket, switching to perfect channel medium\n");
		hwsim_register_wmediumd(notify->net, 0);
	}
	return NOTIFY_DONE;

}

static void __net_exit hwsim_exit_net(struct net *net)
{
	struct hwsim_phy *data, *tmp;
	LIST_HEAD(list);

	spin_lock_bh(&hwsim_radio_lock);
	list_for_each_entry_safe(data, tmp, &hwsim_phys, list) {
		if (!net_eq(wpan_phy_net(data->hw->phy), net))
			continue;

		/* Radios created in init_net are returned to init_net. */
		if (data->netgroup == hwsim_net_get_netgroup(&init_net))
			continue;

		list_move(&data->list, &list);
		rhashtable_remove_fast(&hwsim_radios_rht, &data->rht,
				       hwsim_rht_params);
		hwsim_radios_generation++;
	}
	spin_unlock_bh(&hwsim_radio_lock);

	list_for_each_entry_safe(data, tmp, &list, list) {
		list_del(&data->list);
		hwsim_del_radio(data,
					 wpan_phy_name(data->hw->phy),
					 NULL);
	}

	ida_free(&hwsim_netgroup_ida, hwsim_net_get_netgroup(net));
}

#if IS_REACHABLE(CONFIG_VIRTIO)

static void hwsim_virtio_tx_done(struct virtqueue *vq)
{
	unsigned int len;
	struct sk_buff *skb;
	unsigned long flags;

	spin_lock_irqsave(&hwsim_virtio_lock, flags);
	while ((skb = virtqueue_get_buf(vq, &len)))
		dev_kfree_skb_irq(skb);
	spin_unlock_irqrestore(&hwsim_virtio_lock, flags);
}

static int hwsim_virtio_handle_cmd(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *gnlh;
	struct nlattr *tb[MAC802154_HWSIM_ATTR_MAX + 1];
	struct genl_info info = {};
	int err;

	nlh = nlmsg_hdr(skb);
	gnlh = nlmsg_data(nlh);

	if (skb->len < nlh->nlmsg_len)
		return -EINVAL;

	err = genlmsg_parse(nlh, &hwsim_genl_family, tb, MAC802154_HWSIM_ATTR_MAX,
			    hwsim_genl_policy, NULL);
	if (err) {
		pr_err_ratelimited("hwsim: genlmsg_parse returned %d\n", err);
		return err;
	}

	info.attrs = tb;

	switch (gnlh->cmd) {
	/*case MAC802154_HWSIM_CMD_FRAME:
		hwsim_cloned_frame_received_nl(skb, &info);
		break;
	case MAC802154_HWSIM_CMD_TX_INFO_FRAME:
		hwsim_tx_info_frame_received_nl(skb, &info);
		break;
	case HWSIM_CMD_REPORT_PMSR:
		hwsim_pmsr_report_nl(skb, &info);
		break;*/
	default:
		pr_err_ratelimited("hwsim: invalid cmd: %d\n", gnlh->cmd);
		return -EPROTO;
	}
	return 0;
}

static void hwsim_virtio_rx_work(struct work_struct *work)
{
	struct virtqueue *vq;
	unsigned int len;
	struct sk_buff *skb;
	struct scatterlist sg[1];
	int err;
	unsigned long flags;

	spin_lock_irqsave(&hwsim_virtio_lock, flags);
	if (!hwsim_virtio_enabled)
		goto out_unlock;

	skb = virtqueue_get_buf(hwsim_vqs[HWSIM_VQ_RX], &len);
	if (!skb)
		goto out_unlock;
	spin_unlock_irqrestore(&hwsim_virtio_lock, flags);

	skb->data = skb->head;
	skb_reset_tail_pointer(skb);
	skb_put(skb, len);
	hwsim_virtio_handle_cmd(skb);

	spin_lock_irqsave(&hwsim_virtio_lock, flags);
	if (!hwsim_virtio_enabled) {
		dev_kfree_skb_irq(skb);
		goto out_unlock;
	}
	vq = hwsim_vqs[HWSIM_VQ_RX];
	sg_init_one(sg, skb->head, skb_end_offset(skb));
	err = virtqueue_add_inbuf(vq, sg, 1, skb, GFP_ATOMIC);
	if (WARN(err, "virtqueue_add_inbuf returned %d\n", err))
		dev_kfree_skb_irq(skb);
	else
		virtqueue_kick(vq);
	schedule_work(&hwsim_virtio_rx);

out_unlock:
	spin_unlock_irqrestore(&hwsim_virtio_lock, flags);
}

static void hwsim_virtio_rx_done(struct virtqueue *vq)
{
	schedule_work(&hwsim_virtio_rx);
}

static int init_vqs(struct virtio_device *vdev)
{
	struct virtqueue_info vqs_info[HWSIM_NUM_VQS] = {
		[HWSIM_VQ_TX] = { "tx", hwsim_virtio_tx_done },
		[HWSIM_VQ_RX] = { "rx", hwsim_virtio_rx_done },
	};

	return virtio_find_vqs(vdev, HWSIM_NUM_VQS,
			       hwsim_vqs, vqs_info, NULL);
}

static int fill_vq(struct virtqueue *vq)
{
	int i, err;
	struct sk_buff *skb;
	struct scatterlist sg[1];

	for (i = 0; i < virtqueue_get_vring_size(vq); i++) {
		skb = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!skb)
			return -ENOMEM;

		sg_init_one(sg, skb->head, skb_end_offset(skb));
		err = virtqueue_add_inbuf(vq, sg, 1, skb, GFP_KERNEL);
		if (err) {
			nlmsg_free(skb);
			return err;
		}
	}
	virtqueue_kick(vq);
	return 0;
}

static void remove_vqs(struct virtio_device *vdev)
{
	int i;

	virtio_reset_device(vdev);

	for (i = 0; i < ARRAY_SIZE(hwsim_vqs); i++) {
		struct virtqueue *vq = hwsim_vqs[i];
		struct sk_buff *skb;

		while ((skb = virtqueue_detach_unused_buf(vq)))
			nlmsg_free(skb);
	}

	vdev->config->del_vqs(vdev);
}

static int hwsim_virtio_probe(struct virtio_device *vdev)
{
	int err;
	unsigned long flags;

	spin_lock_irqsave(&hwsim_virtio_lock, flags);
	if (hwsim_virtio_enabled) {
		spin_unlock_irqrestore(&hwsim_virtio_lock, flags);
		return -EEXIST;
	}
	spin_unlock_irqrestore(&hwsim_virtio_lock, flags);

	err = init_vqs(vdev);
	if (err)
		return err;

	virtio_device_ready(vdev);

	err = fill_vq(hwsim_vqs[HWSIM_VQ_RX]);
	if (err)
		goto out_remove;

	spin_lock_irqsave(&hwsim_virtio_lock, flags);
	hwsim_virtio_enabled = true;
	spin_unlock_irqrestore(&hwsim_virtio_lock, flags);

	schedule_work(&hwsim_virtio_rx);
	return 0;

out_remove:
	remove_vqs(vdev);
	return err;
}

static void hwsim_virtio_remove(struct virtio_device *vdev)
{
	hwsim_virtio_enabled = false;

	cancel_work_sync(&hwsim_virtio_rx);

	remove_vqs(vdev);
}

/* MAC802154_HWSIM virtio device id table */
//vertificar VIRTIO_ID_MAC80211_HWSIM
static const struct virtio_device_id id_table[] = {
	//{ VIRTIO_ID_MAC80211_HWSIM, VIRTIO_DEV_ANY_ID },
	{ 42, VIRTIO_DEV_ANY_ID },
	{ 0 }
};
MODULE_DEVICE_TABLE(virtio, id_table);

static struct virtio_driver virtio_hwsim = {
	.driver.name = KBUILD_MODNAME,
	.id_table = id_table,
	.probe = hwsim_virtio_probe,
	.remove = hwsim_virtio_remove,
};

static int hwsim_register_virtio_driver(void)
{
	return register_virtio_driver(&virtio_hwsim);
}

static void hwsim_unregister_virtio_driver(void)
{
	unregister_virtio_driver(&virtio_hwsim);
}
#else
static inline int hwsim_register_virtio_driver(void)
{
	return 0;
}

static inline void hwsim_unregister_virtio_driver(void)
{
}
#endif

static struct notifier_block hwsim_netlink_notifier = {
	.notifier_call = mac802154_hwsim_netlink_notify,
};

static int __init hwsim_init_netlink(void)
{
	int rc;

	printk(KERN_INFO "mac802154_hwsim: initializing netlink\n");

	rc = genl_register_family(&hwsim_genl_family);
	if (rc)
		goto failure;

	rc = netlink_register_notifier(&hwsim_netlink_notifier);
	if (rc) {
		genl_unregister_family(&hwsim_genl_family);
		goto failure;
	}

	return 0;

failure:
	pr_debug("mac802154_hwsim: error occurred in %s\n", __func__);
	return -EINVAL;
}

static __net_init int hwsim_init_net(struct net *net)
{
	return hwsim_net_set_netgroup(net);
}

static struct pernet_operations hwsim_net_ops = {
	.init = hwsim_init_net,
	.exit = hwsim_exit_net,
	.id   = &hwsim_net_id,
	.size = sizeof(struct hwsim_net),
};

static void hwsim_exit_netlink(void)
{
	/* unregister the notifier */
	netlink_unregister_notifier(&hwsim_netlink_notifier);
	/* unregister the family */
	genl_unregister_family(&hwsim_genl_family);
}

static __init int hwsim_init_module(void)
{
	int rc, err;

	if (radios < 0)
		return -EINVAL;
	
	err = rhashtable_init(&hwsim_radios_rht, &hwsim_rht_params);
	if (err)
		return err;

	err = register_pernet_device(&hwsim_net_ops);
	if (err)
		goto out_free_rht;

	err = hwsim_init_netlink();
	if (err)
		goto out_unregister_driver;

	err = hwsim_register_virtio_driver();
	if (err)
		goto out_exit_netlink;

	hwsim_class = class_create("mac802154_hwsim");
	if (IS_ERR(hwsim_class)) {
		err = PTR_ERR(hwsim_class);
		goto out_exit_virtio;
	}

	mac802154hwsim_dev = platform_device_register_simple("mac802154_hwsim",
							     -1, NULL, 0);
	if (IS_ERR(mac802154hwsim_dev)) {
		rc = PTR_ERR(mac802154hwsim_dev);
		goto out_unregister_driver;
	}

	rc = platform_driver_register(&mac802154hwsim_driver);
	if (rc < 0)
		goto out_unregister_pernet;

	return 0;

out_exit_virtio:
	hwsim_unregister_virtio_driver();
out_exit_netlink:
	hwsim_exit_netlink();
out_unregister_pernet:
	unregister_pernet_device(&hwsim_net_ops);
	return rc;
out_unregister_driver:
	platform_driver_unregister(&mac802154hwsim_driver);
out_free_rht:
	rhashtable_destroy(&hwsim_radios_rht);
	return err;
}

static __exit void hwsim_remove_module(void)
{
    pr_debug("mac80211_hwsim: unregister radios\n");
	hwsim_unregister_virtio_driver();
	hwsim_exit_netlink();
	rhashtable_destroy(&hwsim_radios_rht);
	platform_driver_unregister(&mac802154hwsim_driver);
	platform_device_unregister(mac802154hwsim_dev);
	unregister_pernet_device(&hwsim_net_ops);
}

module_init(hwsim_init_module);
module_exit(hwsim_remove_module);