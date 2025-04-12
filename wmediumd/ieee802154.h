/*
 *	wmediumd, wireless medium simulator for mac80211_hwsim kernel module
 *	Copyright (c) 2011 cozybit Inc.
 *
 *	Author:	Javier Lopez	<jlopex@cozybit.com>
 *		Javier Cardona	<javier@cozybit.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version 2
 *	of the License, or (at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 *	02110-1301, USA.
 */

#include <linux/types.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#ifndef IEEE802154_H_
#define IEEE802154_H_

#define IEEE80211_AVAILABLE_RATES 12
#define IEEE80211_TX_MAX_RATES 4
#define IEEE80211_NUM_ACS 4

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define IEEE802154_MAX_DATA_LEN  90

#define FCTL_FTYPE		0x0c
#define FCTL_TODS		0x01
#define FCTL_FROMDS		0x02

#define FTYPE_MGMT		0x00
#define FTYPE_DATA		0x08

#define STYPE_QOS_DATA		0x80

#define QOS_CTL_TAG1D_MASK	0x07

struct ieee802154_sechdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8 level:3,
	   key_id_mode:2,
	   reserved:3;
#elif defined(__BIG_ENDIAN_BITFIELD)
	u8 reserved:3,
	   key_id_mode:2,
	   level:3;
#endif
	u8 key_id;
	__le32 frame_counter;
	union {
		__le32 short_src;
		__le64 extended_src;
	};
};


struct ieee802154_addr {
	u8 mode;
	__le16 pan_id;
	union {
		__le16 short_addr;
		__le64 extended_addr;
	};
};

struct ieee802154_hdr_fc {
	u16 type:3,
	    security_enabled:1,
	    frame_pending:1,
	    ack_request:1,
	    intra_pan:1,
	    reserved:3,
	    dest_addr_mode:2,
	    version:2,
	    source_addr_mode:2;
};

enum ieee80211_ac_number {
	IEEE80211_AC_VO		= 0,
	IEEE80211_AC_VI		= 1,
	IEEE80211_AC_BE		= 2,
	IEEE80211_AC_BK		= 3,
};

static const enum ieee80211_ac_number ieee802_1d_to_ac[8] = {
	IEEE80211_AC_BE,
	IEEE80211_AC_BK,
	IEEE80211_AC_BK,
	IEEE80211_AC_BE,
	IEEE80211_AC_VI,
	IEEE80211_AC_VI,
	IEEE80211_AC_VO,
	IEEE80211_AC_VO
};

struct ieee802154_hdr {
	struct ieee802154_hdr_fc fc;
	unsigned char seq;
	struct ieee802154_addr source;
	struct ieee802154_addr dest;
	struct ieee802154_sechdr sec;
};

#endif /* IEEE802154_H_ */
