#ifndef __SIMPLEDNS_H
#define __SIMPLEDNS_H

#include <arpa/inet.h>
#include "list.h" 


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

struct ResourceRecord  *ResourceRecord_Create(void);
struct ResourceRecord  *ResourceRecord_Init(const char *name, uint32_t type);
struct ResourceRecord  *ResourceRecord_Soa_init(const char *name, const char *mname, const char *rname, uint32_t serial);

#endif
