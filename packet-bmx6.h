/* packet-bmx6.h
 * Definitions for BMX6 packet disassembly structures and routines
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


/** Frame types **/
typedef uint8_t  FRAME_TYPE_T;
#define FRAME_ISSHORT_BIT_SIZE   (1)
#define FRAME_RELEVANCE_BIT_SIZE  (1)
#define FRAME_TYPE_BIT_SIZE    ((8*sizeof(FRAME_TYPE_T)) - FRAME_ISSHORT_BIT_SIZE - FRAME_RELEVANCE_BIT_SIZE)
#define FRAME_TYPE_MASK        MIN( (0x1F) /*some bits reserved*/, ((1<<FRAME_TYPE_BIT_SIZE)-1))
#define FRAME_TYPE_ARRSZ       (FRAME_TYPE_MASK+1)
#define FRAME_HEADER_SHORT_LEN	2
#define	FRAME_HEADER_LONG_LEN	4

#define FRAME_TYPE_RSVD0        0
#define FRAME_TYPE_PROBLEM_ADV  2 
#define FRAME_TYPE_TEST_ADV     3 
#define FRAME_TYPE_HELLO_ADV    4
#define FRAME_TYPE_DEV_REQ      6
#define FRAME_TYPE_DEV_ADV      7
#define FRAME_TYPE_LINK_REQ     8
#define FRAME_TYPE_LINK_ADV     9
#define FRAME_TYPE_RP_ADV      11
#define FRAME_TYPE_DESC_REQ    14
#define FRAME_TYPE_DESC_ADV    15
#define FRAME_TYPE_HASH_REQ    18
#define FRAME_TYPE_HASH_ADV    19
//#define FRAME_TYPE_HELLO_REPS  21
#define FRAME_TYPE_OGM_ADV     22
#define FRAME_TYPE_OGM_ACK     23
#define FRAME_TYPE_NOP         24
#define FRAME_TYPE_MAX         (FRAME_TYPE_ARRSZ-1)
#define FRAME_TYPE_PROCESS_ALL    (255)
#define FRAME_TYPE_PROCESS_NONE   (254)

#define DESCRIPTION0_ID_NAME_LEN 32

/** TLV types **/
#define TLV_TYPE_MASK	FRAME_TYPE_MASK
#define BMX_DSC_TLV_METRIC      0x00
#define BMX_DSC_TLV_UHNA4       0x01
#define BMX_DSC_TLV_UHNA6       0x02
#define BMX_DSC_TLV_TUN6_ADV            0x04
#define BMX_DSC_TLV_TUN4IN6_INGRESS_ADV 0x05
#define BMX_DSC_TLV_TUN6IN6_INGRESS_ADV 0x06
#define BMX_DSC_TLV_TUN4IN6_SRC_ADV     0x07
#define BMX_DSC_TLV_TUN6IN6_SRC_ADV     0x08
#define BMX_DSC_TLV_TUN4IN6_NET_ADV     0x09
#define BMX_DSC_TLV_TUN6IN6_NET_ADV     0x0A
#define BMX_DSC_TLV_JSON_SMS    0x10
#define BMX_DSC_TLV_MAX         (FRAME_TYPE_ARRSZ-1)
#define BMX_DSC_TLV_ARRSZ       (FRAME_TYPE_ARRSZ)

#define MSG_DEV_ADV_SZ	26
#define MSG_LINK_ADV_SZ	6
#define HASH_SHA1_LEN	20
#define MSG_DESC_ADV_SZ	HASH_SHA1_LEN+DESCRIPTION0_ID_NAME_LEN+18

/** OGM_ADV and ACK Frames **/
typedef guint8 AGGREG_SQN_T;
typedef guint16 OGM_MIX_T;
typedef guint16 OGM_SQN_T;
typedef guint16 IID_T;
typedef guint8 OGM_DEST_T;
#define HDR_OGM_ADV_SZ	2;
#define OGM_MIX_BIT_SIZE (sizeof (OGM_MIX_T) * 8)
#define OGM_IIDOFFST_BIT_SIZE (OGM_MIX_BIT_SIZE-(OGM_MANTISSA_BIT_SIZE+OGM_EXPONENT_BIT_SIZE))
#define OGM_IIDOFFST_MASK ((1<<OGM_IIDOFFST_BIT_SIZE)-1)
#define OGM_EXPONENT_BIT_POS (0)
#define OGM_MANTISSA_BIT_POS (0 + OGM_EXPONENT_BIT_SIZE)
#define OGM_IIDOFFST_BIT_POS (0 + OGM_MANTISSA_BIT_SIZE + OGM_EXPONENT_BIT_SIZE)
#define OGM_MANTISSA_BIT_SIZE  5
#define OGM_EXPONENT_BIT_SIZE  5
#define OGM_IID_RSVD_JUMP  (OGM_IIDOFFST_MASK)

/** METRICS **/
#define FM8_EXPONENT_BIT_SIZE  OGM_EXPONENT_BIT_SIZE
#define FM8_MANTISSA_BIT_SIZE  (8-FM8_EXPONENT_BIT_SIZE)
#define FM8_MANTISSA_MASK      ((1<<FM8_MANTISSA_BIT_SIZE)-1)
#define FM8_MANTISSA_MIN       (1)
struct float_u8 {
	union {

		struct {
			unsigned int exp_fmu8 : FM8_EXPONENT_BIT_SIZE;
			unsigned int mantissa_fmu8 : FM8_MANTISSA_BIT_SIZE;
		} __attribute__((packed)) f;
		guint8 u8;
	} val;
};

typedef struct float_u8 FMETRIC_U8_T;


