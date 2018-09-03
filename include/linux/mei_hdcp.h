/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/*
 * Copyright © 2017-2018 Intel Corporation
 *
 * Authors:
 * Ramalingam C <ramalingam.c@intel.com>
 */

#ifndef _LINUX_MEI_HDCP_H
#define _LINUX_MEI_HDCP_H

/* Enumeration of the physical DDI available on the platform */
enum hdcp_physical_port {
	INVALID_PORT = 0x00,	/* Not a valid port */

	DDI_RANGE_BEGIN = 0x01,	/* Beginning of the valid DDI port range */
	DDI_B		= 0x01,		/* Port DDI B */
	DDI_C		= 0x02,		/* Port DDI C */
	DDI_D		= 0x03,		/* Port DDI D */
	DDI_E		= 0x04,		/* Port DDI E */
	DDI_F		= 0x05,		/* Port DDI F */
	DDI_A		= 0x07,		/* Port DDI A */
	DDI_RANGE_END	= DDI_A,/* End of the valid DDI port range */
};

/* The types of HDCP 2.2 ports supported */
enum hdcp_integrated_port_type {
	HDCP_INVALID_TYPE	= 0x00,

	/* HDCP 2.x ports that are integrated into Intel HW */
	INTEGRATED		= 0x01,

	/* HDCP2.2 discrete wired Tx port with LSPCON (HDMI 2.0) solution */
	LSPCON			= 0x02,

	/* HDCP2.2 discrete wired Tx port using the CPDP (DP 1.3) solution */
	CPDP			= 0x03,
};

/*
 * wired_protocol: Supported integrated wired HDCP protocol.
 * Based on this value, Minor difference needed between wired specifications
 * are handled.
 */
enum hdcp_protocol {
	HDCP_PROTOCOL_INVALID,
	HDCP_PROTOCOL_HDMI,
	HDCP_PROTOCOL_DP
};

/* mei_hdcp_data: Input data to the mei_hdcp APIs. */
struct mei_hdcp_data {
	enum hdcp_physical_port port;
	enum hdcp_integrated_port_type port_type;
	enum hdcp_protocol protocol;

	/*
	 * No of streams transmitted on a port.
	 * In case of HDMI & DP SST, single stream will be
	 * transmitted on a port.
	 */
	u16 k;

	/*
	 * Count of RepeaterAuth_Stream_Manage msg propagated.
	 * Initialized to 0 on AKE_INIT. Incremented after every successful
	 * transmission of RepeaterAuth_Stream_Manage message. When it rolls
	 * over re-Auth has to be triggered.
	 */
	u32 seq_num_m;

	/* k(No of Streams per port) x structure of wired_streamid_type */
	struct hdcp2_streamid_type *streams;
};

#endif /* !_LINUX_MEI_HDCP_H */
