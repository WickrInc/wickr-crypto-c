/*
* Copyright © 2012-2020 Wickr Inc.  All rights reserved.
*
* This code is being released for EDUCATIONAL, ACADEMIC, AND CODE REVIEW PURPOSES
* ONLY.  COMMERCIAL USE OF THE CODE IS EXPRESSLY PROHIBITED.  For additional details,
* please see LICENSE
*
* THE CODE IS MADE AVAILABLE "AS-IS" AND WITHOUT ANY EXPRESS OR
* IMPLIED GUARANTEES AS TO FITNESS, MERCHANTABILITY, NON-
* INFRINGEMENT OR OTHERWISE. IT IS NOT BEING PROVIDED IN TRADE BUT ON
* A VOLUNTARY BASIS ON BEHALF OF THE AUTHOR’S PART FOR THE BENEFIT
* OF THE LICENSEE AND IS NOT MADE AVAILABLE FOR CONSUMER USE OR ANY
* OTHER USE OUTSIDE THE TERMS OF THIS LICENSE. ANYONE ACCESSING THE
* CODE SHOULD HAVE THE REQUISITE EXPERTISE TO SECURE THEIR SYSTEM
* AND DEVICES AND TO ACCESS AND USE THE CODE FOR REVIEW PURPOSES
* ONLY. LICENSEE BEARS THE RISK OF ACCESSING AND USING THE CODE. IN
* PARTICULAR, AUTHOR BEARS NO LIABILITY FOR ANY INTERFERENCE WITH OR
* ADVERSE EFFECT THAT MAY OCCUR AS A RESULT OF THE LICENSEE
* ACCESSING AND/OR USING THE CODE ON LICENSEE’S SYSTEM.
*/

#ifndef transport_error_h
#define transport_error_h

/**
 @ingroup wickr_transport_ctx
 @enum wickr_transport_error

 Wickr Transport Context Errors
 
 @var wickr_transport_error::TRANSPORT_ERROR_NONE
 Transport has not reported any errors
 @var wickr_transport_error::TRANSPORT_ERROR_HANDSHAKE_FAILED
 The handshake has reported a failure in finalization due to a negative user identity callback, or an internal error generating keys
 @var wickr_transport_error::TRANSPORT_ERROR_CREATE_HANDSHAKE_FAILED
 A handshake could not be generated for this transport
 @var wickr_transport_error::TRANSPORT_ERROR_START_HANDSHAKE_FAILED
 The handshake returned a bad response code from the start command
 @var wickr_transport_error::TRANSPORT_ERROR_PROCESS_HANDSHAKE_FAILED
 The handshake returned a bad response code while trying to process an inbound packet
 @var wickr_transport_error::TRANSPORT_ERROR_HANDSHAKE_VOLLEY_FAILED
 The handshake failed to properly provide a response packet during processing
 @var wickr_transport_error::TRANSPORT_ERROR_BAD_START_STATUS
 The transport could not be started because it is not in a valid state
 @var wickr_transport_error::TRANSPORT_ERROR_BAD_RX_STATE
 The inbound packet could not be processed because the transport is not in a valid state
 @var wickr_transport_error::TRANSPORT_ERROR_BAD_TX_STATE
 The outbound packet could not be processed because the transport is not in a valid state
 @var wickr_transport_error::TRANSPORT_ERROR_PACKET_ENCODE_FAILED
 An outbound packet failed to be properly encrypted
 @var wickr_transport_error::TRANSPORT_ERROR_PACKET_DECODE_FAILED
 An inbound packet failed to be properly decrypted
 @var wickr_transport_error::TRANSPORT_ERROR_PACKET_SERIALIZATION_FAILED
 A packet failed to be converted into a buffer
 @var wickr_transport_error::TRANSPORT_ERROR_INVALID_RXDATA
 The data contained within a received packet is not in the correct format
 */

typedef enum {
    TRANSPORT_ERROR_NONE,
    TRANSPORT_ERROR_HANDSHAKE_FAILED,
    TRANSPORT_ERROR_CREATE_HANDSHAKE_FAILED,
    TRANSPORT_ERROR_START_HANDSHAKE_FAILED,
    TRANSPORT_ERROR_PROCESS_HANDSHAKE_FAILED,
    TRANSPORT_ERROR_HANDSHAKE_VOLLEY_FAILED,
    TRANSPORT_ERROR_BAD_START_STATUS,
    TRANSPORT_ERROR_BAD_RX_STATE,
    TRANSPORT_ERROR_BAD_TX_STATE,
    TRANSPORT_ERROR_PACKET_ENCODE_FAILED,
    TRANSPORT_ERROR_PACKET_DECODE_FAILED,
    TRANSPORT_ERROR_PACKET_SERIALIZATION_FAILED,
    TRANSPORT_ERROR_INVALID_RXDATA
} wickr_transport_error;

#endif /* transport_error_h */
