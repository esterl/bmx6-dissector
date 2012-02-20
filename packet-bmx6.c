/* packet-bmx6.c
 * Routines for BMX6 protocol packet disassembly
 * By Ester Lopez <esterl@ac.upc.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <arpa/inet.h>
#include <epan/packet.h>
#include "packet-bmx6.h"

#define PROTO_TAG_BMX	"BMX6"

static const value_string bmx_frame_types[] = {
    { FRAME_TYPE_RSVD0, "RSVD frame" },
    { FRAME_TYPE_PROBLEM_ADV, "Problem advertisement frame" },
    { FRAME_TYPE_TEST_ADV, "Test advertisement frame" },
    { FRAME_TYPE_HELLO_ADV, "Hello advertisement" },
    { FRAME_TYPE_DEV_REQ, "Device request" },
    { FRAME_TYPE_DEV_ADV, "Device advertisement" },
    { FRAME_TYPE_LINK_REQ, "Link request" },
    { FRAME_TYPE_LINK_ADV, "Link advertisement" },
    { FRAME_TYPE_RP_ADV, "Response advertisement" },
    { FRAME_TYPE_DESC_REQ, "Description request" },
    { FRAME_TYPE_DESC_ADV, "Description advertisement" },
    { FRAME_TYPE_HASH_REQ, "Hash request" },
    { FRAME_TYPE_HASH_ADV, "Hash advertisement" },
    { FRAME_TYPE_OGM_ADV, "Originator message advertisement" },
    { FRAME_TYPE_OGM_ACK, "Originator message acknowledgment" },
    { FRAME_TYPE_NOP, "No operation" },
    { 0, NULL }
};

static const value_string bmx_tlv_types[] = {
	{ BMX_DSC_TLV_METRIC, "Metric TLV"},
	{ BMX_DSC_TLV_UHNA4, "HNA4 TLV"},
	{ BMX_DSC_TLV_UHNA6, "HNA6 TLV"},
	{ BMX_DSC_TLV_TUN6_ADV, "TUN6 TLV"},
	{ BMX_DSC_TLV_TUN4IN6_INGRESS_ADV, "TUN4IN6_INGRESS_ADV TLV"},
	{ BMX_DSC_TLV_TUN6IN6_INGRESS_ADV, "TUN6IN6_INGRESS_ADV TLV"},
	{ BMX_DSC_TLV_TUN4IN6_SRC_ADV, "TUN4IN6_SRC_ADV TLV"},
	{ BMX_DSC_TLV_TUN6IN6_SRC_ADV, "TUN6IN6_SRC_ADV TLV"},
	{ BMX_DSC_TLV_TUN4IN6_NET_ADV, "TUN4IN6_NET_ADV TLV"},
	{ BMX_DSC_TLV_TUN6IN6_NET_ADV, "TUN6IN6_NET_ADV TLV"},
	{ BMX_DSC_TLV_JSON_SMS, "JSON_SMS TLV"},
	{ 0, NULL }
};

static int proto_bmx6 = -1;

static int hf_bmx6_version = -1;
static int hf_bmx6_len = -1;
static int hf_bmx6_tx_iid = -1;
static int hf_bmx6_link_sqn = -1;
static int hf_bmx6_pkt_sqn = -1;
static int hf_bmx6_local_id = -1;
static int hf_bmx6_dev_idx = -1;
static int hf_bmx6_frame_is_short = -1;
static int hf_bmx6_frame_is_relevant = -1;
static int hf_bmx6_frame_length8 = -1;
static int hf_bmx6_frame_length16 = -1;
static int hf_bmx6_reserved_length = -1;
static int hf_bmx6_frame_type = -1;
static int hf_bmx6_hello_sqn = -1;
static int hf_bmx6_tlv_type = -1;

/* Packet header */
static gint ett_bmx6 = -1;
static gint ett_bmx6_version = -1;
static gint ett_bmx6_len = -1;
static gint ett_bmx6_tx_iid = -1;
static gint ett_bmx6_link_sqn = -1;
static gint ett_bmx6_pkt_sqn = -1;
static gint ett_bmx6_local_id = -1;
static gint ett_bmx6_dev_idx = -1;
static gint ett_bmx6_frame_header = -1;

/* HELLO_ADV frame */
static gint ett_bmx6_hello_adv = -1;

/* RP_ADV frame */
static gint ett_bmx6_rp_adv = -1;

/* LINK_REQ frame */
static gint ett_bmx6_link_req = -1;

/* LINK_ADV frame */
static gint ett_bmx6_link_adv = -1;
static gint ett_bmx6_link = -1;

/* DEV_REQ frame */
static gint ett_bmx6_dev_req = -1;

/* DEV_ADV frame */
static gint ett_bmx6_dev_adv = -1;

/* HASH_REQ frame */
static gint ett_bmx6_hash_req = -1;

/* HASH_ADV frame */
static gint ett_bmx6_hash_adv = -1;

/* DESC_REQ frame */
static gint ett_bmx6_desc_req = -1;

/* DESC_ADV frame */
static gint ett_bmx6_desc_adv = -1;

/* OGM_ADV frame */
static gint ett_bmx6_ogm_adv = -1;

/* OGM_ACK frame */
static gint ett_bmx6_ogm_ack = -1;

/* TLVs */
static gint ett_bmx6_tlv_metric = -1;
static gint ett_bmx6_tlv_uhna4 = -1;
static gint ett_bmx6_tlv_uhna6 = -1;
static gint ett_bmx6_tlv_tun6_adv = -1;
static gint ett_bmx6_tlv_tun4in6_ingress = -1;
static gint ett_bmx6_tlv_tun6in6_ingress = -1;
static gint ett_bmx6_tlv_tun4in6_src = -1;
static gint ett_bmx6_tlv_tun6in6_src = -1;
static gint ett_bmx6_tlv_tun4in6_net = -1;
static gint ett_bmx6_tlv_tun6in6_net = -1;
static gint ett_bmx6_tlv_json_sms = -1;
static gint ett_bmx6_tlv_header = -1;

static void
dissect_hello_adv(tvbuff_t *tvb, proto_tree *tree, int offset, int version){

	guint8 reserved;
	guint16 sqn;
	
	sqn = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Hello sequence number: %u", sqn);
	offset +=2;
	if(version == 13){
		reserved = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(tree,tvb, offset, 1, "Reserved: 0x%x", reserved);
	}
}

static void
dissect_link_req(tvbuff_t *tvb, proto_tree *tree, int offset){

	guint32 dest_id;
	
	dest_id = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Destination local id: 0x%x", dest_id);
	
}

static void
dissect_link_adv(tvbuff_t *tvb, proto_tree *tree, int offset, int n){
	
	guint8 tx_dev, peer_dev;
	guint16 dev_sqn;
	guint32 peer_id;
	
	dev_sqn = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Device sequence number reference: %u", dev_sqn);
	offset +=2;

	int i =1;
	
	proto_tree *link1;
	proto_item *ti;
	
	while(n>=i){
		//New item:
		ti = proto_tree_add_text(tree, tvb, offset, 6, "link %i:", i);
		link1 = proto_item_add_subtree(ti, ett_bmx6_link);
		
		tx_dev = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(link1, tvb, offset, 1, "Transmitter device identifier: %u", tx_dev);
		offset ++;
		
		peer_dev = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(link1, tvb, offset, 1, "Peer device identifier: %u", peer_dev);
		offset ++;
			
		peer_id = tvb_get_ntohl(tvb, offset);
		proto_tree_add_text(link1, tvb, offset, 4, "Peer local id: 0x%x", peer_id);
		offset +=4;

		i++;
	}
}

static void
dissect_dev_req(tvbuff_t *tvb, proto_tree *tree, int offset){
	
	guint32 dst_id = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Destination local id: 0x%x", dst_id);
}

static void
dissect_dev_adv(tvbuff_t *tvb, proto_tree *tree, int offset, int n){
	guint8 dev_idx, channel;
	guint16 dev_sqn;
	guint64 mac;
	FMETRIC_U8_T tx_min, tx_max;
	int i;
	char str[INET6_ADDRSTRLEN];
	struct e_in6_addr ipv6;
	proto_tree *dev1;
	proto_item *ti;
	
	//Sequence number
	dev_sqn = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Device advertisement sequence number: %u", dev_sqn);
	offset+=2;

	i =1;
	while(n>=i){
		//New item:
		ti = proto_tree_add_text(tree, tvb, offset, 6, "Device %i:", i);
		dev1 = proto_item_add_subtree(ti, ett_bmx6_link);
		
		dev_idx = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(dev1, tvb, offset, 1, "Device index: %u", dev_idx);
		offset++;
		
		channel = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(dev1, tvb, offset, 1, "Channel: %u", channel);
		offset++;
		
		tx_min.val.u8 = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(dev1, tvb, offset, 1, "Transmitter min bitrate: %u^%u = %f", tx_min.val.f.mantissa_fmu8, 
			tx_min.val.f.exp_fmu8, pow(tx_min.val.f.mantissa_fmu8, tx_min.val.f.exp_fmu8));
		offset++;
		
		tx_max.val.u8 = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(dev1, tvb, offset, 1, "Transmitter max bitrate: %u^%u = %f", tx_max.val.f.mantissa_fmu8, 
			tx_max.val.f.exp_fmu8, pow(tx_max.val.f.mantissa_fmu8, tx_max.val.f.exp_fmu8));
		offset++;
		
		tvb_get_ipv6(tvb, offset, &ipv6);
		proto_tree_add_text(dev1, tvb, offset, 16, "Local IPv6 address: %s",
			inet_ntop(AF_INET6, &(ipv6), str, INET6_ADDRSTRLEN));
		offset += 16;
		
		mac = tvb_get_ntoh48(tvb, offset);
		proto_tree_add_text(dev1, tvb, offset, 6, "Mac address: %x",mac);
		offset +=6;

		i++;
	}
}

static void
dissect_hash_req(tvbuff_t *tvb, proto_tree *tree, int offset, int N){
	
	guint32 dst_id;
	int i;
	
	dst_id = tvb_get_ntohl(tvb, offset);
	
	proto_tree_add_text(tree, tvb, offset, 4, "Destination local id: 0x%x", dst_id);
	offset += 4;
	
	i =1;
	while(N>=i){
	
		proto_tree_add_text(tree, tvb, offset, 2, "ReceiverIID4x: %u", tvb_get_ntohs(tvb,offset));
		offset += 2;
		i++;
	}		
}

static void
dissect_hash_adv(tvbuff_t *tvb, proto_tree *tree, int offset){

	guint16 transmitter_iid;
	
	transmitter_iid = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "TransmitterIID4x: %u", transmitter_iid);
	offset +=2;
	
	proto_tree_add_text(tree, tvb, offset, -1, "Description hash");
}

static int
dissect_bmx6_tlv(tvbuff_t *tvb, proto_item *tlv_item, int offset){
//gboolean 	tvb_bytes_exist (const tvbuff_t *, const gint offset, const gint length)

	guint8 type;
	guint16 length;
	int bit_offset, num, header_length;
	proto_tree *tlv, *tlv_header;
	proto_item *ti, *th_item;
	
	
	//Add the proper subtree:
	type = tvb_get_guint8(tvb, offset) & 0x1f;
	proto_item_append_text(tlv_item, val_to_str(type, bmx_tlv_types, "Unknown tlv type: %u"));
	switch(type) {
	case BMX_DSC_TLV_METRIC:
		tlv = proto_item_add_subtree(tlv_item, ett_bmx6_tlv_metric);
		break;
	case BMX_DSC_TLV_UHNA4:
		tlv = proto_item_add_subtree(tlv_item, ett_bmx6_tlv_uhna4);
		break;
	case BMX_DSC_TLV_UHNA6:
		tlv = proto_item_add_subtree(tlv_item, ett_bmx6_tlv_uhna6);
		break;
	case BMX_DSC_TLV_TUN6_ADV:
		tlv = proto_item_add_subtree(tlv_item, ett_bmx6_tlv_tun6_adv);
		break;
	case BMX_DSC_TLV_TUN4IN6_INGRESS_ADV:
		tlv = proto_item_add_subtree(tlv_item, ett_bmx6_tlv_tun4in6_ingress);
		break;
	case BMX_DSC_TLV_TUN6IN6_INGRESS_ADV:
		tlv = proto_item_add_subtree(tlv_item, ett_bmx6_tlv_tun6in6_ingress);
		break;
	case BMX_DSC_TLV_TUN4IN6_SRC_ADV:
		tlv = proto_item_add_subtree(tlv_item, ett_bmx6_tlv_tun4in6_src);
		break;
	case BMX_DSC_TLV_TUN6IN6_SRC_ADV:
		tlv = proto_item_add_subtree(tlv_item, ett_bmx6_tlv_tun6in6_src);
		break;
	case BMX_DSC_TLV_TUN4IN6_NET_ADV:
		tlv = proto_item_add_subtree(tlv_item, ett_bmx6_tlv_tun4in6_net);
		break;
	case BMX_DSC_TLV_TUN6IN6_NET_ADV:
		tlv = proto_item_add_subtree(tlv_item, ett_bmx6_tlv_tun6in6_net);
		break;
	case BMX_DSC_TLV_JSON_SMS:
		tlv = proto_item_add_subtree(tlv_item, ett_bmx6_tlv_json_sms);
		break;
	default:
		//TODO new ett
		tlv = proto_item_add_subtree(tlv_item, ett_bmx6_hello_adv);
		break;
	}
	
	//TLV header
	th_item = proto_tree_add_text(tlv, tvb, offset, -1, "TLV header: ");
	tlv_header= proto_item_add_subtree(th_item, ett_bmx6_tlv_header);
	//is_short
	bit_offset = offset*8;
	ti = proto_tree_add_bits_item(tlv_header, hf_bmx6_frame_is_short, tvb, bit_offset, 1, FALSE);
	//is_relevant
	proto_tree_add_bits_item(tlv_header, hf_bmx6_frame_is_relevant, tvb, bit_offset+1, 1, FALSE);
	//type
	proto_tree_add_item(tlv_header, hf_bmx6_tlv_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	
	//length
	if(ti->finfo->value.value.uinteger){
		length = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tlv_header, hf_bmx6_frame_length8, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		header_length = FRAME_HEADER_SHORT_LEN;
	}else{
		//reserved
		proto_tree_add_item(tlv_header, hf_bmx6_reserved_length, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		length = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(tlv_header, hf_bmx6_frame_length16, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		header_length = FRAME_HEADER_LONG_LEN;
	}
	proto_item_set_len(th_item, header_length);
	proto_item_set_len(tlv_item, length);
	
	switch(type) {
	case BMX_DSC_TLV_METRIC:
	case BMX_DSC_TLV_UHNA4:
	case BMX_DSC_TLV_UHNA6:
	case BMX_DSC_TLV_TUN6_ADV:
	case BMX_DSC_TLV_TUN4IN6_INGRESS_ADV:
	case BMX_DSC_TLV_TUN6IN6_INGRESS_ADV:
	case BMX_DSC_TLV_TUN4IN6_SRC_ADV:
	case BMX_DSC_TLV_TUN6IN6_SRC_ADV:
	case BMX_DSC_TLV_TUN4IN6_NET_ADV:
	case BMX_DSC_TLV_TUN6IN6_NET_ADV:
	case BMX_DSC_TLV_JSON_SMS:
	default:
		break;
	}
	
	return length;
}

static void
dissect_desc_adv16(tvbuff_t *tvb, proto_tree *tree, int offset){
	gchar* pkid;
	guint8 reserved, reserved_ttl;
	guint16 code_version,capabilities,dsc_sqn,min,range,tx_int,extension_len, transmitter_iid;
	guint8 *name;
	int i, processed, n;
	proto_item *tlv_item;
	
	//Header
	//TransmitterIID4x
	transmitter_iid = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "TransmitterIID4x: %u", transmitter_iid);
	offset +=2;

	//Data
	//Global id:
	name = tvb_get_ephemeral_string(tvb, offset, DESCRIPTION0_ID_NAME_LEN);
	proto_tree_add_text(tree, tvb, offset, DESCRIPTION0_ID_NAME_LEN, "Name : %s", name);
	offset += DESCRIPTION0_ID_NAME_LEN;
	//PKID
	pkid = tvb_bytes_to_str(tvb, offset, HASH_SHA1_LEN);
	proto_tree_add_text(tree, tvb, offset, HASH_SHA1_LEN, "pkid: 0x%s", pkid);
	offset+=HASH_SHA1_LEN;
	//Code version:
	code_version = tvb_get_ntohs(tvb,offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Code version: %u", code_version);
	offset+=2;
	//Capabilities:
	capabilities = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Capabilities: 0x%x", capabilities);
	offset +=2;
	//Description sequence number:
	dsc_sqn = tvb_get_ntohs(tvb,offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Description sequence number: %u", dsc_sqn);
	offset +=2;
	//OGM sqn minim:
	min = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Originator message min sqn: %u", min);
	offset +=2;
	//OGM sqn range:
	range = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Originator message range: %u", range);
	offset +=2;
	//tx_interval:
	tx_int = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Transmission interval: %u", tx_int);
	offset +=2;
	//reserved_ttl:
	reserved_ttl = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1, "Reserved TTL: %u", reserved_ttl);
	offset++;
	//reserved:
	reserved = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1, "Reserved: %u", reserved);
	offset++;
	//Extension length:
	extension_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Extension Length: %u", extension_len);
	offset +=2;
	
	//Do TLVs:
	i=1;
	
	while(processed < extension_len ){
		//Create TLV tree:
		tlv_item = proto_tree_add_text(tree, tvb, offset, -1, "TLV [%u]: ", i);
		n = dissect_bmx6_tlv(tvb, tlv_item, offset);
		offset += n;
		processed +=n;
		i++;
	}
}

static void
dissect_desc_adv(tvbuff_t *tvb, proto_tree *tree, int offset) {

	guint16 transmitterIID4x,version,tlvs_len,dsc_sqn,cap,min,range,tx_int;
	
	//TransmitterIID4x
	transmitterIID4x = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "TransmitterIID4x: %u", transmitterIID4x);
	offset +=2;
	
	//Description ID:
	guint8 *name;
	name = tvb_get_ephemeral_string(tvb, offset, DESCRIPTION0_ID_NAME_LEN);
	proto_tree_add_text(tree, tvb, offset, DESCRIPTION0_ID_NAME_LEN,
		"Name : %s", name);
	offset += DESCRIPTION0_ID_NAME_LEN;
	guint64 rand = tvb_get_letoh64(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 8, "Random part of the name: 0x%x", rand);
	offset += 8;
	
	//Code version:
	version = tvb_get_ntohs(tvb,offset);
	proto_tree_add_text(tree, tvb, offset,2,
		"Code version: %u", version);
	offset += 2;
	
	//Description tlvs len:
	tlvs_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Description TLVs length: %u", tlvs_len);
	offset +=2;

	//Description sequence number:
	dsc_sqn = tvb_get_ntohs(tvb,offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Description sequence number: %u", dsc_sqn);
	offset +=2;
	
	//Capabilities:
	cap = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Capabilities: 0x%x", cap);
	offset +=2;
	
	//OGM sqn minim:
	min = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Originator message min sqn: %u", min);
	offset +=2;
	
	//OGM sqn range:
	range = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Originator message range: %u", range);
	offset +=2;
	
	//tx_interval
	tx_int = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2, "Transmission interval: %u", tx_int);
	offset +=2;

	//ttl_max
	guint8 ttl = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1, "Max TTL: %u", ttl);
	offset++;
}

static void
dissect_ogm_adv(tvbuff_t *tvb, proto_tree *tree, int offset, int N){
	AGGREG_SQN_T aggr_sqn;
	guint8 dest;
	OGM_MIX_T mix;
	OGM_SQN_T ogm_sqn;
	IID_T absolute, neigh;
	
	guint16 ogm_offset;
	int i;
	
	//TODO it is still hardcoded that aggr_sqn is a guint8
	//aggregation_sqn
	aggr_sqn = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1, "Aggregation sequence number: %u", aggr_sqn);
	offset++;
	
	//ogm_destination_array
	dest = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1, "OGM destination array: 0x%x", dest);
	offset++;
	
	//Skip the destination bytes
	offset += dest;
	
	i=1;
	neigh=0;
	//TODO add new subtree?
	while(i<=N){
		mix = tvb_get_ntohs(tvb, offset);
		proto_tree_add_text(tree, tvb, offset, 2, "Mix : 0x%x", mix);
		offset += 2;
		
		ogm_offset = ((mix >> OGM_IIDOFFST_BIT_POS) & OGM_IIDOFFST_MASK);
		if(ogm_offset == OGM_IID_RSVD_JUMP){
			absolute = tvb_get_ntohs(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, 2, "%u. IID: %d", i, absolute);
			offset += 2;
			neigh = absolute;
		} else{
			ogm_sqn = tvb_get_ntohs(tvb, offset);
			proto_tree_add_text(tree, tvb, offset, 2, "%u. OGM sequence number: %u. IID jump from %d to %d", i, ogm_sqn, neigh, neigh+ogm_offset);
			offset +=2;
			neigh += ogm_offset;
		}
		i++;    
	}
}

static void
dissect_ogm_ack(tvbuff_t *tvb, proto_tree *tree, int offset){
	OGM_DEST_T dest;
	AGGREG_SQN_T sqn;
	
	//OGM destination:
	dest = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1, "Destination: 0x%x", dest);
	offset++;
	
	//Aggregation sqn being ack'ed:
	sqn = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1, "Aggregation sequence number: %u", sqn);
	offset++;
}

static int
dissect_bmx6_frame(tvbuff_t *tvb, proto_item *frame,int version, int offset)
{
//gboolean 	tvb_bytes_exist (const tvbuff_t *, const gint offset, const gint length)


	guint8 type;
	proto_tree *frame1, *frame_header;
	proto_item *ti, *fh_item;
	//Length
	guint16 initial,length;
	int bit_offset, num, header_length;
	
	initial=offset;
	//Add the proper subtree:
	type = tvb_get_guint8(tvb, offset) & 0x1f;
	proto_item_append_text(frame, val_to_str(type, bmx_frame_types, "Unknown frame type: %u"));
	switch(type) {
	case FRAME_TYPE_HELLO_ADV:
		frame1 = proto_item_add_subtree(frame, ett_bmx6_hello_adv);
		break;
	case FRAME_TYPE_LINK_REQ:
		frame1 = proto_item_add_subtree(frame, ett_bmx6_link_req);
		break;
	case FRAME_TYPE_LINK_ADV:
		frame1 = proto_item_add_subtree(frame, ett_bmx6_link_adv);
		break;
	case FRAME_TYPE_DEV_REQ:
		frame1 = proto_item_add_subtree(frame, ett_bmx6_dev_req);
		break;
	case FRAME_TYPE_DEV_ADV:
		frame1 = proto_item_add_subtree(frame, ett_bmx6_dev_adv);
		break;
	case FRAME_TYPE_HASH_REQ:
		frame1 = proto_item_add_subtree(frame, ett_bmx6_hash_req);
		break;
	case FRAME_TYPE_HASH_ADV:
		frame1 = proto_item_add_subtree(frame, ett_bmx6_hash_adv);
		break;
	case FRAME_TYPE_DESC_REQ:
		frame1 = proto_item_add_subtree(frame, ett_bmx6_desc_req);
		break;
	case FRAME_TYPE_DESC_ADV:
		frame1 = proto_item_add_subtree(frame, ett_bmx6_desc_req);
		break;
	case FRAME_TYPE_OGM_ADV:
		frame1 = proto_item_add_subtree(frame, ett_bmx6_ogm_adv);
		break;
	case FRAME_TYPE_OGM_ACK:
		frame1 = proto_item_add_subtree(frame, ett_bmx6_ogm_ack);
		break;
	default:
		//TODO new ett
		frame1 = proto_item_add_subtree(frame, ett_bmx6_hello_adv);
		break;
	}
	
	//Frame header:text(bmx_tree, tvb, offset, -1, "Frame [%u]: ", i);
	fh_item = proto_tree_add_text(frame1, tvb, offset, -1, "Frame header: ");
	frame_header= proto_item_add_subtree(fh_item, ett_bmx6_frame_header);
	//is_short
	bit_offset = offset*8;
	ti = proto_tree_add_bits_item(frame_header, hf_bmx6_frame_is_short, tvb, bit_offset, 1, FALSE);
	//is_relevant
	proto_tree_add_bits_item(frame_header, hf_bmx6_frame_is_relevant, tvb, bit_offset+1, 1, FALSE);
	//type
	proto_tree_add_item(frame_header, hf_bmx6_frame_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	
	//length
	if(ti->finfo->value.value.uinteger){
		length = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(frame_header, hf_bmx6_frame_length8, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		header_length = FRAME_HEADER_SHORT_LEN;
	}else{
		//reserved
		proto_tree_add_item(frame_header, hf_bmx6_reserved_length, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		length = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(frame_header, hf_bmx6_frame_length16, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		header_length = FRAME_HEADER_LONG_LEN;
	}
	proto_item_set_len(fh_item, header_length);
	proto_item_set_len(frame, length);
	
	
	switch(type) {
	case FRAME_TYPE_HELLO_ADV:
		dissect_hello_adv(tvb, frame1, offset, version);
		break;
	case FRAME_TYPE_LINK_REQ:
		dissect_link_req(tvb, frame1, offset);
		break;
	case FRAME_TYPE_LINK_ADV:
		num = (length - header_length) / MSG_LINK_ADV_SZ;
		//Length = 2 (frame_hdr) + 2 (link_hdr) + 6 * N_links
		dissect_link_adv(tvb, frame1, offset, (length -4)/6);
		break;
	case FRAME_TYPE_DEV_REQ:
		dissect_dev_req(tvb, frame1, offset);
		break;
	case FRAME_TYPE_DEV_ADV:
		num = (length - header_length) / MSG_DEV_ADV_SZ;
		dissect_dev_adv(tvb, frame1, offset, num);
		break;
	case FRAME_TYPE_HASH_REQ:
		dissect_hash_req(tvb, frame1, offset, (length -6)/2);
		break;
	case FRAME_TYPE_HASH_ADV:
		dissect_hash_adv(tvb, frame1, offset);
		break;
	case FRAME_TYPE_DESC_REQ:
		dissect_hash_req(tvb, frame1, offset, (length -6)/2);
		break;
	case FRAME_TYPE_DESC_ADV:
		if(version >= 16)
			dissect_desc_adv16(tvb,frame1,offset);
		else
			dissect_desc_adv(tvb, frame1, offset);
		break;
	case FRAME_TYPE_OGM_ADV:
		dissect_ogm_adv(tvb, frame1, offset, (length -2)/4);
		break;
	case FRAME_TYPE_OGM_ACK:
		dissect_ogm_ack(tvb, frame1, offset);
		break;
	default:
		break;
	}
	return initial+length;
}

static void
dissect_bmx6(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    int version,i;

    proto_item *bmx_item = NULL;
    proto_item *bmx_sub_item = NULL;
    proto_tree *bmx_tree = NULL;
    proto_tree *bmx_header_tree = NULL;
    
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_BMX);
    /* Clear out stuff in the info column */
    if(check_col(pinfo->cinfo,COL_INFO)){
        col_clear(pinfo->cinfo,COL_INFO);
    }

    /* Dissect packet header */
    if (tree) { /* we are being asked for details */

		bmx_item = proto_tree_add_item(tree, proto_bmx6, tvb, 0, -1, ENC_NA);
		bmx_tree = proto_item_add_subtree(bmx_item, ett_bmx6);
		//version
		version = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(bmx_tree, hf_bmx6_version, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset +=2;
		//pkt_length
		proto_tree_add_item(bmx_tree, hf_bmx6_len, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset +=2;
		//transmitterIID
		proto_tree_add_item(bmx_tree, hf_bmx6_tx_iid, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset +=2;
		//link_adv_sqn
		proto_tree_add_item(bmx_tree, hf_bmx6_link_sqn, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset +=2;
		//pkt_sqn
		proto_tree_add_item(bmx_tree, hf_bmx6_pkt_sqn, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset +=4;
		//local_id
		proto_tree_add_item(bmx_tree, hf_bmx6_local_id, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset +=4;
		//dev_idx
		proto_tree_add_item(bmx_tree, hf_bmx6_dev_idx, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset +=1;
		
		/* Do frames */
		i=1;
		while(tvb_length(tvb) - offset >0 ){
			//Create frame tree:
			bmx_sub_item = proto_tree_add_text(bmx_tree, tvb, offset, -1, "Frame [%u]: ", i);
			offset = dissect_bmx6_frame(tvb, bmx_sub_item, version, offset);
			i++;
		}
    }
}

void
proto_register_bmx6(void)
{
	//BMX6 fields:
    static hf_register_info hf[] = {
	{ &hf_bmx6_version,
          { "version", "bmx6.version", FT_UINT8, BASE_DEC, NULL, 0x0,
                "BMX6 VERSION", HFILL }},
	{ &hf_bmx6_len,
          { "length", "bmx6.len", FT_UINT16, BASE_DEC, NULL, 0x0,
                "Packet length", HFILL }},
	{ &hf_bmx6_tx_iid,
          { "transmitter IID", "bmx6.tx_iid", FT_UINT16, BASE_DEC, NULL, 0x0,
                "transmitter IID", HFILL }},
	{ &hf_bmx6_link_sqn,
          { "link sqn", "bmx6.link_sqn", FT_UINT16, BASE_DEC, NULL, 0x0,
                "Link advertisment sequence number", HFILL }},
	{ &hf_bmx6_pkt_sqn,
          { "packet sqn", "bmx6.pkt_sqn", FT_UINT32, BASE_DEC, NULL, 0x0,
                "Packet sequence number", HFILL }},
	{ &hf_bmx6_local_id,
          { "Local ID", "bmx6.local_id", FT_UINT32, BASE_HEX, NULL, 0x0,
               NULL, HFILL }},
	{ &hf_bmx6_dev_idx,
          { "Device idx", "bmx6.dev_idx", FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }},
    { &hf_bmx6_frame_is_short,
          { "Short frame", "bmx6.frame.short", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x0,
                "Lenth of the frame format", HFILL }},
    { &hf_bmx6_frame_is_relevant,
          { "Relevant frame", "bmx6.frame.relevant", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x0,
                "Relevancy of the frame", HFILL }},
	{ &hf_bmx6_frame_type,
		{ "Frame type", "bmx6.frame.type", FT_UINT8, BASE_DEC, VALS(bmx_frame_types), FRAME_TYPE_MASK,
			"Frame type", HFILL}}, 
	{ &hf_bmx6_tlv_type,
		{ "TLV type", "bmx6.tlv.type", FT_UINT8, BASE_DEC, VALS(bmx_tlv_types), TLV_TYPE_MASK,
			"TLV type", HFILL}}, 
	{ &hf_bmx6_frame_length8,
		{ "Frame length", "bmx6.frame.length", FT_UINT8, BASE_DEC, NULL, 0x00,
			"Length of the frame" , HFILL}},
	{ &hf_bmx6_frame_length16,
		{ "Frame length (16 bit)", "bmx6.frame.length", FT_UINT16, BASE_DEC, NULL, 0x00,
			"Length of the frame", HFILL}},
	{ &hf_bmx6_hello_sqn,
		{ "Hello sqn", "bmx6.hello.sqn", FT_UINT16, BASE_DEC,NULL, 0x0,
			"Hello sequence number", HFILL}},
    };

	//BMX6 trees
    static gint *ett[] = {
        &ett_bmx6,
        &ett_bmx6_version,
        &ett_bmx6_len,
        &ett_bmx6_tx_iid,
        &ett_bmx6_link_sqn,
        &ett_bmx6_pkt_sqn,
        &ett_bmx6_local_id,
        &ett_bmx6_dev_idx,
        &ett_bmx6_frame_header,
        &ett_bmx6_hello_adv,
        &ett_bmx6_rp_adv,
        &ett_bmx6_link_req,
        &ett_bmx6_link_adv,
        &ett_bmx6_link,
        &ett_bmx6_dev_req,
        &ett_bmx6_dev_adv,
        &ett_bmx6_hash_req,
        &ett_bmx6_hash_adv,
        &ett_bmx6_desc_req,
        &ett_bmx6_desc_adv,
        &ett_bmx6_ogm_adv,
        &ett_bmx6_ogm_ack,
        &ett_bmx6_tlv_header,
        &ett_bmx6_tlv_metric,
		&ett_bmx6_tlv_uhna4,
		&ett_bmx6_tlv_uhna6,
		&ett_bmx6_tlv_tun6_adv,
		&ett_bmx6_tlv_tun4in6_ingress,
		&ett_bmx6_tlv_tun6in6_ingress,
		&ett_bmx6_tlv_tun4in6_src,
		&ett_bmx6_tlv_tun6in6_src,
		&ett_bmx6_tlv_tun4in6_net,
		&ett_bmx6_tlv_tun6in6_net,
		&ett_bmx6_tlv_json_sms,
    };

	//Protocol, field and trees registrations
    proto_bmx6 = proto_register_protocol("BMX6", "BMX6", "bmx6");
    proto_register_field_array(proto_bmx6, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));


}

void
proto_reg_handoff_bmx6(void)
{
    dissector_handle_t bmx6_handle;

    bmx6_handle = create_dissector_handle(dissect_bmx6, proto_bmx6);
    dissector_add_uint("udp.port", 6240, bmx6_handle);
}
