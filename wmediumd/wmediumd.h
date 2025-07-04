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

#ifndef WMEDIUMD_H_
#define WMEDIUMD_H_

#define MAC802154_HWSIM_TX_CTL_REQ_TX_STATUS	2
#define MAC802154_HWSIM_TX_CTL_NO_ACK		(1 << 1)
#define MAC802154_HWSIM_TX_STAT_ACK		(1 << 2)

#define MAC802154_HWSIM_CMD_REGISTER 9
#define MAC802154_HWSIM_CMD_FRAME 10
#define MAC802154_HWSIM_CMD_TX_INFO_FRAME 11

#define IEEE802154_ADDR_SHORT 2
#define IEEE802154_ADDR_EXTENDED 3

/* mac802154 hwsim netlink attributes
 *
 * @MAC802154_HWSIM_ATTR_UNSPEC: unspecified attribute to catch error
 * @MAC802154_HWSIM_ATTR_RADIO_ID: u32 attribute to identify the radio
 * @MAC802154_HWSIM_ATTR_EDGE: nested attribute of edges
 * @MAC802154_HWSIM_ATTR_EDGES: list if nested attributes which contains the
 *	edge information according the radio id
 * @__MAC802154_HWSIM_ATTR_MAX: enum limit
 */
enum {
	MAC802154_HWSIM_ATTR_UNSPEC,
	MAC802154_HWSIM_ATTR_RADIO_ID,
	MAC802154_HWSIM_ATTR_RADIO_EDGE,
	MAC802154_HWSIM_ATTR_RADIO_EDGES,
	MAC802154_HWSIM_ATTR_COOKIE,
	MAC802154_HWSIM_ATTR_PAD,
	MAC802154_HWSIM_ATTR_FRAME,
	MAC802154_HWSIM_ATTR_ADDR_TRANSMITTER,
	MAC802154_HWSIM_ATTR_ADDR_RECEIVER,
	MAC802154_HWSIM_ATTR_TX_INFO,
	MAC802154_HWSIM_ATTR_FLAGS,
	__MAC802154_HWSIM_ATTR_MAX,
};
#define MAC802154_HWSIM_ATTR_MAX (__MAC802154_HWSIM_ATTR_MAX - 1)

/* mac802154 hwsim edge netlink attributes
 *
 * @MAC802154_HWSIM_EDGE_ATTR_UNSPEC: unspecified attribute to catch error
 * @MAC802154_HWSIM_EDGE_ATTR_ENDPOINT_ID: radio id where the edge points to
 * @MAC802154_HWSIM_EDGE_ATTR_LQI: LQI value which the endpoint radio will
 *	receive for this edge
 * @__MAC802154_HWSIM_ATTR_MAX: enum limit
 */
enum {
	MAC802154_HWSIM_EDGE_ATTR_UNSPEC,
	MAC802154_HWSIM_EDGE_ATTR_ENDPOINT_ID,
	MAC802154_HWSIM_EDGE_ATTR_LQI,
	__MAC802154_HWSIM_EDGE_ATTR_MAX,
};

#define MAC802154_HWSIM_EDGE_ATTR_MAX (__MAC802154_HWSIM_EDGE_ATTR_MAX - 1)

#define VERSION_NR 1

#define SNR_DEFAULT 30
#define GAIN_DEFAULT 5
#define GAUSS_RANDOM_DEFAULT 1
#define HEIGHT_DEFAULT 1
#define AP_DEFAULT 2
#define MEDIUM_ID_DEFAULT 0
#define EXTENDED_ADDR_LEN 8
#define AP_DEFAULT_PORT 4001
#define PAGE_SIZE 4096

#include <stdint.h>
#include <stdbool.h>
#include <syslog.h>
#include <stdio.h>

#include "list.h"
#include "ieee802154.h"

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;

#define TIME_FMT "%lld.%06lld"
#define TIME_ARGS(a) ((unsigned long long)(a)->tv_sec), ((unsigned long long)(a)->tv_nsec/1000)

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ARGS(a) a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7]

#ifndef min
#define min(x,y) ((x) < (y) ? (x) : (y))
#endif

#define NOISE_LEVEL	(-91)
#define CCA_THRESHOLD	(-90)
#define ENABLE_MEDIUM_DETECTION	true

enum En_OperationMode
{
	LOCAL,
	REMOTE
};

struct wqueue {
	struct list_head frames;
	int cw_min;
	int cw_max;
};

struct station {
	int index;
	u8 short_addr[16];
	int addr_len;
	u8 extended_addr[64];		/* virtual interface mac address */
	u8 hwaddr[8];		/* hardware address of hwsim radio */
	double x, y, z;			/* position of the station [m] */
	double dir_x, dir_y;		/* direction of the station [meter per MOVE_INTERVAL] */
	int tx_power;			/* transmission power [dBm] */
	int gain;			/* Antenna Gain [dBm] */
	//int height;			/* Antenna Height [m] */
	int gRandom;     /* Gaussian Random */
	int isap; 		/* verify whether the node is ap */
	double freq;			/* frequency [Mhz] */
	struct wqueue queues[IEEE80211_NUM_ACS];
	struct list_head list;
    int medium_id;
};

struct wmediumd {
	int op_mode;
	int timerfd;
	int net_sock;
	struct nl_sock *sock;
    bool enable_medium_detection;
	int num_stas;
	struct list_head pending_txinfo_frames;
	struct list_head stations;
	struct station **sta_array;
	int *snr_matrix;
	double *error_prob_matrix;
	double **station_err_matrix;
	struct intf_info *intf;
	struct timespec intf_updated;
#define MOVE_INTERVAL	(3) /* station movement interval [sec] */
	struct timespec next_move;
	void *path_loss_param;
	float *per_matrix;
	int per_matrix_row_num;
	int per_matrix_signal_min;
	int fading_coefficient;
	int noise_threshold;

	struct nl_cb *cb;
	int family_id;

	int (*get_link_snr)(struct wmediumd *, struct station *,
			    struct station *);
	double (*get_error_prob)(struct wmediumd *, double, unsigned int, u32,
				 int, struct station *, struct station *);
	int (*calc_path_loss)(void *, struct station *,
			      struct station *);
	void (*move_stations)(struct wmediumd *);
	int (*get_fading_signal)(struct wmediumd *);

	u8 log_lvl;
};

struct hwsim_tx_rate {
	signed char idx;
	unsigned char count;
};

struct frame {
	struct list_head list;		/* frame queue list */
	struct timespec expires;	/* frame delivery (absolute) */
	bool acked;
	u64 cookie;
	u32 freq;
	int flags;
	int lqi;
	int duration;
	int tx_rates_count;
	struct station *sender;
	uint8_t dest_mode;
	struct hwsim_tx_rate tx_rates[IEEE80211_TX_MAX_RATES];
	size_t data_len;
	u8 data[0];			/* frame contents */
};

struct log_distance_model_param {
	double path_loss_exponent;
	double Xg;
};

struct itu_model_param {
	int nFLOORS;
	int lF;
	int pL;
};

struct log_normal_shadowing_model_param {
	int sL;
	double path_loss_exponent;
};

struct free_space_model_param {
	int sL;
};

struct two_ray_ground_model_param {
	int sL;
};

struct intf_info {
	int lqi;
	int duration;
	double prob_col;
};

void station_init_queues(struct station *station);
double get_error_prob_from_snr(double snr, unsigned int rate_idx, u32 freq,
			       int frame_len);
bool timespec_before(struct timespec *t1, struct timespec *t2);
int read_per_file(struct wmediumd *ctx, const char *file_name);
int w_logf(struct wmediumd *ctx, u8 level, const char *format, ...);
int w_flogf(struct wmediumd *ctx, u8 level, FILE *stream, const char *format, ...);
int index_to_rate(size_t index, u32 freq);
void detect_mediums(struct wmediumd *ctx, struct station *src, struct station *dest);

#endif /* WMEDIUMD_H_ */
