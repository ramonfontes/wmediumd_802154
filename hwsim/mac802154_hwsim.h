#ifndef __MAC802154_HWSIM_H
#define __MAC802154_HWSIM_H


/* mac802154 hwsim netlink commands
 * @HWSIM_CMD_REGISTER: request to register and received all broadcasted
 *		frames by any mac802154_hwsim radio device.
 * @MAC802154_HWSIM_CMD_UNSPEC: unspecified command to catch error
 * @MAC802154_HWSIM_CMD_GET_RADIO: fetch information about existing radios
 * @MAC802154_HWSIM_CMD_SET_RADIO: change radio parameters during runtime
 * @MAC802154_HWSIM_CMD_NEW_RADIO: create a new radio with the given parameters
 *	returns the radio ID (>= 0) or negative on errors, if successful
 *	then multicast the result
 * @MAC802154_HWSIM_CMD_DEL_RADIO: destroy a radio, reply is multicasted
 * @MAC802154_HWSIM_CMD_GET_EDGE: fetch information about existing edges
 * @MAC802154_HWSIM_CMD_SET_EDGE: change edge parameters during runtime
 * @MAC802154_HWSIM_CMD_DEL_EDGE: delete edges between radios
 * @MAC802154_HWSIM_CMD_NEW_EDGE: create a new edge between two radios
 * @__MAC802154_HWSIM_CMD_MAX: enum limit
 */
enum {
	MAC802154_HWSIM_CMD_UNSPEC,

	MAC802154_HWSIM_CMD_GET_RADIO,
	MAC802154_HWSIM_CMD_SET_RADIO,
	MAC802154_HWSIM_CMD_NEW_RADIO,
	MAC802154_HWSIM_CMD_DEL_RADIO,

	MAC802154_HWSIM_CMD_GET_EDGE,
	MAC802154_HWSIM_CMD_SET_EDGE,
	MAC802154_HWSIM_CMD_DEL_EDGE,
	MAC802154_HWSIM_CMD_NEW_EDGE,
	MAC802154_HWSIM_CMD_REGISTER,
	MAC802154_HWSIM_CMD_FRAME,

	__MAC802154_HWSIM_CMD_MAX,
};

#define MAC802154_HWSIM_CMD_MAX (__MAC802154_HWSIM_MAX - 1)

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

/**
 * DOC: Frame transmission support over virtio
 *
 * Frame transmission is also supported over virtio to allow communication
 * with external entities.
 */

/**
 * enum hwsim_vqs - queues for virtio frame transmission
 *
 * @HWSIM_VQ_TX: send frames to external entity
 * @HWSIM_VQ_RX: receive frames and transmission info reports
 * @HWSIM_NUM_VQS: enum limit
 */
enum hwsim_vqs {
	HWSIM_VQ_TX,
	HWSIM_VQ_RX,
	HWSIM_NUM_VQS,
};

#endif /* __MAC802154_HWSIM_H */
