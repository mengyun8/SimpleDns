#ifndef __SIMPLEDNS_H
#define __SIMPLEDNS_H

#include "list.h" 

#define RRLEN		256

/* These values are taken from RFC1537 */
#define DEFAULT_REFRESH     (60 * 60 * 8)
#define DEFAULT_RETRY       (60 * 60 * 2)
#define DEFAULT_EXPIRE      (60 * 60 * 24 * 7)
#define DEFAULT_MINIMUM     (60 * 60 * 24)

/*
* This software is licensed under the CC0.
*
* This is a _basic_ DNS Server for educational use.
*  It doesn't prevent invalid packets from crashing
*  the server.
*
* To test start the program and issue a DNS request:
*  dig @127.0.0.1 foo.bar.com 
*/


/*
* Masks and constants.
*/

static const uint32_t QR_MASK = 0x8000;
static const uint32_t OPCODE_MASK = 0x7800;
static const uint32_t AA_MASK = 0x0400;
static const uint32_t TC_MASK = 0x0200;
static const uint32_t RD_MASK = 0x0100;
static const uint32_t RA_MASK = 0x8000;
static const uint32_t RCODE_MASK = 0x000F;

/* Response Type */
enum {
	RT_NoError = 0,
	RT_FormErr = 1,
	RT_ServFail = 2,
	RT_NxDomain = 3,
	RT_NotImp = 4,
	RT_Refused = 5,
	RT_YXDomain = 6,
	RT_YXRRSet = 7,
	RT_NXRRSet = 8,
	RT_NotAuth = 9,
	RT_NotZone = 10
};

/* Resource Record Types */
enum {
	RR_A = 1,
	RR_NS = 2,
	RR_CNAME = 5,
	RR_SOA = 6,
	RR_PTR = 12,
	RR_MX = 15,
	RR_TXT = 16,
	RR_AAAA = 28,
	RR_SRV = 33
};

/* Operation Code */
enum {
	QUERY_OperationCode = 0, /* standard query */
	IQUERY_OperationCode = 1, /* inverse query */
	STATUS_OperationCode = 2, /* server status request */
	NOTIFY_OperationCode = 4, /* request zone transfer */
	UPDATE_OperationCode = 5 /* change resource records */
};

/* Response Code */
enum {
	NoError_ResponseCode = 0,
	FormatError_ResponseCode = 1,
	ServerFailure_ResponseCode = 2,
	NameError_ResponseCode = 3
};

/* Query Type */
enum {
	IXFR_QueryType = 251,
	AXFR_QueryType = 252,
	MAILB_QueryType = 253,
	MAILA_QueryType = 254,
	STAR_QueryType = 255
};

/* Question Section */
struct Question {
	char *qName;
	uint16_t qType;
	uint16_t qClass;
	struct Question* next; // for linked list
};

/* Data part of a Resource Record */
union ResourceData {
	struct {
		char *txt_data;
	} txt_record;
	struct {
		//uint8_t addr[4];
		struct in_addr addr;
	} a_record;
	struct {
		char* MName;
		char* RName;
		uint32_t serial;
		uint32_t refresh;
		uint32_t retry;
		uint32_t expire;
		uint32_t minimum;
	} soa_record;
	struct {
		char *name;
	} ns_record;
	struct {
		char *name;
	} cname_record;
	struct {
		char *name;
	} ptr_record;
	struct {
		uint16_t preference;
		char *exchange;
	} mx_record;
	struct {
		uint8_t addr[16];
		//struct in6_addr addr;
	} aaaa_record;
	struct {
		uint16_t priority;
		uint16_t weight;
		uint16_t port;
		char *target;
	} srv_record;
};

/* Resource Record Section */
struct ResourceRecord {
	char 	*name;
	char	*origin;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rd_length;
	union ResourceData rd_data;
	struct ResourceRecord* next; // for linked list
};

struct Message {
	uint16_t id; /* Identifier */

	/* Flags */
	uint16_t qr; /* Query/Response Flag */
	uint16_t opcode; /* Operation Code */
	uint16_t aa; /* Authoritative Answer Flag */
	uint16_t tc; /* Truncation Flag */
	uint16_t rd; /* Recursion Desired */
	uint16_t ra; /* Recursion Available */
	uint16_t rcode; /* Response Code */

	uint16_t qdCount; /* Question Count */
	uint16_t anCount; /* Answer Record Count */
	uint16_t nsCount; /* Authority Record Count */
	uint16_t arCount; /* Additional Record Count */

	/* At least one question; questions are copied to the response 1:1 */
	struct Question* questions;

	/*
	* Resource records to be send back.
	* Every resource record can be in any of the following places.
	* But every place has a different semantic.
	*/
	struct ResourceRecord* answers;
	struct ResourceRecord* authorities;
	struct ResourceRecord* additionals;

	struct in_addr cliaddr;
};


#endif
