#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <sched.h>

#include <event2/event.h>
#include <event2/event_struct.h>

#define BUF_SIZE 	1500
#define DOMAINLEN	256

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
*  dig @127.0.0.1 -p 9000 foo.bar.com 
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

int get_A_Record(uint8_t addr[4], const char domain_name[])
{
	if(strcmp("foo.bar.com", domain_name) == 0)
	{
		addr[0] = 192;
		addr[1] = 168;
		addr[2] = 1;
		addr[3] = 1;
		return 0;
	}
	else
	{
		return -1;
	}
}

int get_AAAA_Record(uint8_t addr[16], const char domain_name[])
{
	if(strcmp("foo.bar.com", domain_name) == 0)
	{
		addr[0] = 0xfe;
		addr[1] = 0x80;
		addr[2] = 0x00;
		addr[3] = 0x00;
		addr[4] = 0x00;
		addr[5] = 0x00;
		addr[6] = 0x00;
		addr[7] = 0x00;
		addr[8] = 0x00;
		addr[9] = 0x00;
		addr[10] = 0x00;
		addr[11] = 0x00;
		addr[12] = 0x00;
		addr[13] = 0x00;
		addr[14] = 0x00;
		addr[15] = 0x00;
		return 0;
	}
	else
	{
		return -1;
	}
}


/*
* Debugging functions.
*/

void print_hex(uint8_t* buf, size_t len)
{
	int i;
	printf("%u bytes:\n", len);
	for(i = 0; i < len; ++i)
		printf("%02x ", buf[i]);
	printf("\n");
}

void print_resource_record(struct ResourceRecord* rr)
{
	int i;
	while(rr)
	{
		printf("  ResourceRecord { name '%s', type %u, class %u, ttl %u, rd_length %u, ",
				rr->name,
				rr->type,
				rr->class,
				rr->ttl,
				rr->rd_length
		);

		union ResourceData *rd = &rr->rd_data;
		switch(rr->type)
		{
			case RR_A:
				printf("Address Resource Record { address ");
			
				printf("%s", inet_ntoa(rd->a_record.addr));
//				for(i = 0; i < 4; ++i)
//					printf("%s%u", (i ? "." : ""), rd->a_record.addr[i]);
			
				printf(" }");
				break;
			case RR_NS:
				printf("Name Server Resource Record { name %u}",
					rd->ns_record.name
				);
				break;
			case RR_CNAME:
				printf("Canonical Name Resource Record { name %u}",
					rd->cname_record.name
				);
				break;
			case RR_SOA:
				printf("SOA { MName '%s', RName '%s', serial %u, refresh %u, retry %u, expire %u, minimum %u }",
					rd->soa_record.MName,
					rd->soa_record.RName,
					rd->soa_record.serial,
					rd->soa_record.refresh,
					rd->soa_record.retry,
					rd->soa_record.expire,
					rd->soa_record.minimum
				);
				break;
			case RR_PTR:
				printf("Pointer Resource Record { name '%s' }",
					rd->ptr_record.name
				);
				break;
			case RR_MX:
				printf("Mail Exchange Record { preference %u, exchange '%s' }",
					rd->mx_record.preference,
					rd->mx_record.exchange
				);
				break;
			case RR_TXT:
				printf("Text Resource Record { txt_data '%s' }",
					rd->txt_record.txt_data
				);
				break;
			case RR_AAAA:
				printf("AAAA Resource Record { address ");
			
				
				//for(i = 0; i < 16; ++i)
				//	printf("%s%02x", (i ? ":" : ""), rd->aaaa_record.addr[i]);
			
				printf(" }");
				break;
			default:
				printf("Unknown Resource Record { ??? }");
		}
		printf("}\n");
		rr = rr->next;
	}
}

void print_query(struct Message* msg)
{
	printf("QUERY { ID: %02x", msg->id);
	printf(". FIELDS: [ QR: %u, OpCode: %u ]", msg->qr, msg->opcode);
	printf(", QDcount: %u", msg->qdCount);
	printf(", ANcount: %u", msg->anCount);
	printf(", NScount: %u", msg->nsCount);
	printf(", ARcount: %u,\n", msg->arCount);

	struct Question* q = msg->questions;
	while(q)
	{
		printf("  Question { qName '%s', qType %u, qClass %u }\n",
			q->qName,
			q->qType,
			q->qClass
		);
		q = q->next;
	}

	print_resource_record(msg->answers);
	print_resource_record(msg->authorities);
	print_resource_record(msg->additionals);

	printf("Clinet:%s", inet_ntoa(msg->cliaddr));

	printf("}\n");
}


/*
* Basic memory operations.
*/
uint8_t get8bits( const uint8_t** buffer ) {
	uint8_t value;

	memcpy( &value, *buffer, 1);
	*buffer += 1;

	return ntohs( value );
}

size_t get16bits( const uint8_t** buffer ) {
	uint16_t value;

	memcpy( &value, *buffer, 2 );
	*buffer += 2;

	return ntohs( value );
}

uint32_t get32bits( const uint8_t** buffer ) {
	uint32_t value;

	memcpy( &value, *buffer, 4 );
	*buffer += 4;

	return ntohl( value );
}

void put8bits( uint8_t** buffer, uint8_t value ) {
	memcpy( *buffer, &value, 1 );
	*buffer += 1;
}

void put16bits( uint8_t** buffer, uint16_t value ) {
	value = htons( value );
	memcpy( *buffer, &value, 2 );
	*buffer += 2;
}

void put32bits( uint8_t** buffer, uint32_t value ) {
	value = htonl( value );
	memcpy( *buffer, &value, 4 );
	*buffer += 4;
}

void putcname(uint8_t** buffer, const uint8_t* domain)
{
	uint8_t* buf = *buffer;
	const uint8_t* beg = domain;
	const uint8_t* pos;
	int len = 0;
	int i = 0;

	while(pos = strchr(beg, '.'))
	{
		len = pos - beg;
		buf[i] = len;
		i += 1;
		memcpy(buf+i, beg, len);
		i += len;

		beg = pos + 1;
	}
	len = strlen(domain) - (beg - domain);

	buf[i] = len;
	i += 1;
	memcpy(buf + i, beg, len);
	i += len;

	buf[i] = 0;
	i += 1;
	*buffer += i;
}

/*
* Deconding/Encoding functions.
*/

// 3foo3bar3com0 => foo.bar.com
char* decode_domain_name(const uint8_t** buffer)
{
	uint8_t name[DOMAINLEN];
	const uint8_t* buf = *buffer;
	int j = 0;
	int i = 0;
	while (buf[i] != 0)
	{
		//if(i >= buflen || i > sizeof(name))
		//	return NULL;
		
		if(i != 0)
		{
			name[j] = '.';
			j += 1;
		}

		int len = buf[i];
		i += 1;

		memcpy(name+j, buf + i, len);
		i += len;
		j += len;
	}

	name[j] = '\0';

	*buffer += i + 1; //also jump over the last 0

	return strdup(name);
}

// foo.bar.com => 3foo3bar3com0
void encode_domain_name(uint8_t** buffer, const uint8_t* domain)
{
	uint8_t* buf = *buffer;
	const uint8_t* beg = domain;
	const uint8_t* pos;
	int len = 0;
	int i = 0;

	while(pos = strchr(beg, '.'))
	{
		len = pos - beg;
		buf[i] = len;
		i += 1;
		memcpy(buf+i, beg, len);
		i += len;

		beg = pos + 1;
	}

	len = strlen(domain) - (beg - domain);

	buf[i] = len;
	i += 1;

	memcpy(buf + i, beg, len);
	i += len;

	buf[i] = 0;
	i += 1;

	*buffer += i;
}

void Message_decode_header(struct Message* msg, const uint8_t** buffer)
{
	msg->id = get16bits(buffer);

	uint32_t fields = get16bits(buffer);
	msg->qr = (fields & QR_MASK) >> 15;
	msg->opcode = (fields & OPCODE_MASK) >> 11;
	msg->aa = (fields & AA_MASK) >> 10;
	msg->tc = (fields & TC_MASK) >> 9;
	msg->rd = (fields & RD_MASK) >> 8;
	msg->ra = (fields & RA_MASK) >> 7;
	msg->rcode = (fields & RCODE_MASK) >> 0;

	msg->qdCount = get16bits(buffer);
	msg->anCount = get16bits(buffer);
	msg->nsCount = get16bits(buffer);
	msg->arCount = get16bits(buffer);
}

void Message_encode_header(struct Message* msg, uint8_t** buffer)
{
	put16bits(buffer, msg->id);

	int fields = 0;
	fields |= (msg->qr << 15) & QR_MASK;
	fields |= (msg->rcode << 0) & RCODE_MASK;
	// TODO: insert the rest of the fields
	put16bits(buffer, fields);

	put16bits(buffer, msg->qdCount);
	put16bits(buffer, msg->anCount);
	put16bits(buffer, msg->nsCount);
	put16bits(buffer, msg->arCount);
}

void Question_init(struct Question *que)
{
	memset(que, 0, sizeof(struct Question));
}

void Message_unpackage(struct Message *msg, const uint8_t *buffer, size_t *len)
{
	char name[DOMAINLEN];
	int i;
	struct Question	*q = NULL;

	Message_decode_header(msg, &buffer);

#if 0
	if((msg->anCount + msg->nsCount) != 0)
	{
		printf("Only questions expected!\n");
		*len = -1;
		return;
	}
#endif

	// parse questions
	uint32_t qcount = msg->qdCount;
	struct Question* qs = msg->questions;
	for (i = 0; i < qcount; ++i)
	{
		q = malloc(sizeof(struct Question));
		Question_init(q);

		q->qName = decode_domain_name(&buffer);
		q->qType = get16bits(&buffer);
		q->qClass = get16bits(&buffer);

		//prepend question to questions list
		q->next = qs; 
		msg->questions = q;
	}

	uint8_t  opt_owner;
	uint16_t opt_type;
	opt_owner = get8bits(&buffer);
	opt_type = get16bits(&buffer);
	if (opt_owner != 0 || opt_type != 41) /* Opt record */ 
	{
		/* Not EDNS.  */
		return;
	}
	uint16_t opt_class;
	uint8_t  opt_version;
	uint16_t opt_flags;
	uint16_t opt_rdlen;
	uint16_t opt_nsid;
	uint8_t  opt_rcode;

	uint16_t opt_code;
	uint16_t opt_len;
	uint16_t opt_FAMILY;
	uint8_t opt_src_mask;
	uint8_t opt_scope_mask;

	opt_class = get16bits(&buffer);
	opt_rcode = get8bits(&buffer);
	opt_version = get8bits(&buffer);
	opt_flags = get16bits(&buffer);
	opt_rdlen = get16bits(&buffer);

	if (opt_rdlen >= 12)
	{
		opt_code = get16bits(&buffer);
		opt_len = get16bits(&buffer);
		opt_FAMILY = get16bits(&buffer);          
		opt_src_mask = get8bits(&buffer);
		opt_scope_mask = get8bits(&buffer);
	}
	else
	{
		return;
	}

	if (opt_len  >= 7 && opt_code == 8) /* Opt code edns subnet client */ 
	{                                      
		uint32_t addr = htonl(get32bits(&buffer));
		msg->cliaddr = *(struct in_addr *)&addr;
	//	printf( " >> %s\n", inet_ntoa(*(struct in_addr *)&addr));
	}

	// We do not expect any resource records to parse here.
	return;
}

int Resolve_A_Record(struct ResourceRecord* rr)
{
	if (strcmp(rr->name, "www.a.com") == 0)
	{
		rr->type = RR_CNAME;
		rr->rd_data.cname_record.name = strdup("abc.a.com");
		rr->rd_length = strlen("abc.a.com") + 2;
		rr->ttl = (long)60 * 60;
		return 0;
	}
	rr->rd_length = 4;
	rr->ttl = (long)60 * 60; //in seconds; 0 means no caching
	inet_pton(AF_INET, "192.168.10.123", (void *)&rr->rd_data.a_record.addr);
	return 0;
}

int Resolve_AAAA_Record(struct ResourceRecord* rr)
{
	rr->rd_length = 16;
	rr->ttl = (long)60 * 60; //in seconds; 0 means no caching
	inet_pton(AF_INET6, "0:0:0:0:0:FFFF:204.152.189.116", (void *)&rr->rd_data.aaaa_record.addr);
	return 0;
}

//int Resolve_SOA_Record(const char *zone, const char *name, char *mname, char *rname, uint32_t *serial)
int Resolve_SOA_Record(struct ResourceRecord* rr)
{
	rr->rd_data.soa_record.MName = strdup("ns1.b.com");
	rr->rd_data.soa_record.RName = strdup("root.b.com");
	rr->rd_data.soa_record.serial = 2017182013;
	rr->rd_data.soa_record.refresh = DEFAULT_REFRESH;
	rr->rd_data.soa_record.retry = DEFAULT_RETRY;
	rr->rd_data.soa_record.expire = DEFAULT_EXPIRE;
	rr->rd_data.soa_record.minimum = DEFAULT_MINIMUM;
	rr->rd_length = strlen(rr->rd_data.soa_record.MName) + strlen(rr->rd_data.soa_record.RName) + 4 + 20;
	return 0;
}

int ResourceRecord_Resolve(struct ResourceRecord* rr)
{
	int	rc = 0;
	// We only can only answer two question types so far
	// and the answer (resource records) will be all put
	// into the answers list.
	// This behavior is probably non-standard!
	switch (rr->type)
	{
		case RR_A:
			rc = Resolve_A_Record(rr);
			if(rc < 0)
				return -1;
			break;
		case RR_AAAA:
			rc = Resolve_AAAA_Record(rr);
			//rr->rd_length = 16;
			//rc = get_AAAA_Record(rr->rd_data.aaaa_record.addr, rr->name);
			if(rc < 0)
				return -1;
			break;
		case RR_CNAME:
			rr->rd_length = strlen("aa.b.com") + 2;
			rr->rd_data.cname_record.name = strdup("aa.b.com");
			break;
		case RR_SOA:
			rr->rd_length = strlen(" ns1.b.com  root.b.com ") + 20;
			rr->rd_data.soa_record.MName = strdup("ns1.b.com");
			rr->rd_data.soa_record.RName = strdup("root.b.com");
			rr->rd_data.soa_record.serial = 2017182013;
			rr->rd_data.soa_record.refresh = DEFAULT_REFRESH;
			rr->rd_data.soa_record.retry = DEFAULT_RETRY;
			rr->rd_data.soa_record.expire = DEFAULT_EXPIRE;
			rr->rd_data.soa_record.minimum = DEFAULT_MINIMUM;
			break;
		/*
		case NS_RR:
		case CNAME_RR:
		case SOA_RR:
		case PTR_RR:
		case MX_RR:
		case TXT_RR:
		*/
		default:
			printf("Cannot answer question of type %d.\n", rr->type);
			return -1;
	}

	return 0;
}

struct ResourceRecord  *ResourceRecord_Init(const char *name, uint32_t type)
{
	struct ResourceRecord *tmp = NULL;

	tmp = malloc(sizeof(struct ResourceRecord));
	memset(tmp, 0, sizeof(struct ResourceRecord));
	tmp->name = strdup(name);
	tmp->origin = NULL;
	tmp->type = type;
	tmp->class = 0x0001;
	tmp->next = NULL;
	return tmp;
}

void ResourceRecord_Free(struct ResourceRecord  *rr)
{
	if (!rr)
		return;

	if (rr->name)
		free(rr->name);

	if (rr->origin)
		free(rr->origin);

	switch (rr->type)
	{
		case RR_A:
			break;
		case RR_AAAA:
			break;
		case RR_CNAME:
			free(rr->rd_data.cname_record.name);
			break;
		case RR_NS:
			free(rr->rd_data.ns_record.name);
			break;
		case RR_SOA:
			free(rr->rd_data.soa_record.MName);
			free(rr->rd_data.soa_record.RName);
			break;
		default:
			break;
	}
	free(rr);
}

struct ResourceRecord  *ResourceRecord_Soa_init(const char *name, const char *mname, const char *rname, uint32_t serial)
{
	struct ResourceRecord *rr = malloc(sizeof(struct ResourceRecord));
	if (!rr)
		return NULL;

	memset(rr, 0, sizeof(struct ResourceRecord));
	rr->name = strdup(name);
	rr->type = RR_SOA;
	rr->ttl = 86400;
	rr->class = 0x0001;
	rr->next = NULL;
	return rr;
}

void ResourceRecord_Add_Answer(struct Message *msg, struct ResourceRecord* rr)
{
	struct ResourceRecord *tmp = NULL;
	tmp = msg->answers;

	if (!tmp)
	{
		msg->answers = rr;
	}
	else
	{
		while (tmp->next)
		{
			tmp = tmp->next;
		}
		tmp->next = rr;
	}
	msg->anCount ++;
}


void ResourceRecord_add_Author(struct Message *msg, struct ResourceRecord* rr)
{
	struct ResourceRecord *tmp = NULL;
	tmp = msg->authorities;

	if (!tmp)
	{
		msg->authorities = rr;
	}
	else
	{
		while (tmp->next)
		{
			tmp = tmp->next;
		}
		tmp->next = rr;
	}
	msg->nsCount ++;
}


int ResourceRecord_Add(struct Message *msg, struct ResourceRecord *rr)
{
	if (rr->type == RR_SOA)
	{
		ResourceRecord_add_Author(msg, rr);
	}
	else if (rr->type == RR_A || rr->type == RR_AAAA|| rr->type == RR_NS || rr->type == RR_CNAME)
	{
		ResourceRecord_Add_Answer(msg, rr);
	}
	return 0;
}

int  Message_Putrr(struct Message *msg, const char *name, uint32_t type, const char *rdata, uint32_t ttl)
{
	int	rc = 0;
	struct ResourceRecord *rr = ResourceRecord_Init(name, type);
	if (!rr)
		return -1;

	switch (rr->type)
	{
		case RR_A:
			rr->rd_length = 4;
			rr->ttl = ttl;
			inet_pton(AF_INET, rdata, (void *)&rr->rd_data.a_record.addr);
			break;
		case RR_AAAA:
			rr->rd_length = 16;
			rr->ttl = ttl;
			inet_pton(AF_INET6, rdata, (void *)&rr->rd_data.aaaa_record.addr);
			break;
		case RR_CNAME:
			rr->rd_length = strlen(rdata) + 2;
			rr->rd_data.cname_record.name = strdup(rdata);
			break;
		default:
			printf("Cannot answer question of type %d.\n", rr->type);
			return -1;
	}
	ResourceRecord_Add(msg, rr);

	return 0;
}

int Message_Putsoa(struct Message *msg, const char *name, const char *mname, const char *rname, uint32_t serial)
{
	int	rc = 0;
	struct ResourceRecord *rr = ResourceRecord_Init(name, RR_SOA);
	if (!rr)
		return -1;
	rr->rd_data.soa_record.MName = strdup(mname);
	rr->rd_data.soa_record.RName = strdup(rname);
	rr->rd_data.soa_record.serial = serial;
	rr->rd_data.soa_record.refresh = DEFAULT_REFRESH;
	rr->rd_data.soa_record.retry = DEFAULT_RETRY;
	rr->rd_data.soa_record.expire = DEFAULT_EXPIRE;
	rr->rd_data.soa_record.minimum = DEFAULT_MINIMUM;
	rr->rd_length = strlen(rr->rd_data.soa_record.MName) + strlen(rr->rd_data.soa_record.RName) + 24;
	return 0;
}

// For every question in the message add a appropiate resource record
// in either section 'answers', 'authorities' or 'additionals'.
int Message_resolve(struct Message *msg)
{
	struct ResourceRecord* beg;
	struct ResourceRecord* rr;
	struct Question* q;
	int rc;

	char		qname[256] = {0};
	uint16_t	type = 0;
	uint16_t	class = 0;

	// leave most values intact for response
	msg->qr = 1; // this is a response
	msg->aa = 1; // this server is authoritative
	msg->ra = 0; // no recursion available
	msg->rcode = RT_NoError;

	//should already be 0
	msg->anCount = 0;
	msg->nsCount = 0;
	msg->arCount = 0;

	//for every question append resource records
	q = msg->questions;
	while (q)
	{
		strcpy(qname, q->qName);
		type = q->qType;
		class = q->qClass;
find_cname:
		rr = ResourceRecord_Init(qname, type);
		if (!rr)
			return -1;

		if (ResourceRecord_Resolve(rr) < 0)
		{
			msg->rcode = RT_NotImp;
			break;
		}
		ResourceRecord_Add(msg, rr);
		if (rr->type != type && rr->type == RR_CNAME)
		{
			strcpy(qname, rr->rd_data.cname_record.name);
			goto find_cname;
		}
		// process next question
		q = q->next;
	}
	return 0;
}

int encode_resource_records(struct ResourceRecord* rr, uint8_t** buffer)
{
	int i;
	uint32_t A_addr;
	uint64_t AAAA_addr;
	while (rr)
	{
		/* Answer questions by attaching resource sections. */
		putcname(buffer, rr->name);
		put16bits(buffer, rr->type);
		put16bits(buffer, rr->class);
		put32bits(buffer, rr->ttl);
		put16bits(buffer, rr->rd_length);
		
		switch (rr->type)
		{
			case RR_A:
				A_addr = htonl(*(uint32_t *)&(rr->rd_data.a_record.addr));
				put32bits(buffer, A_addr);
				break;
			case RR_AAAA:
				for(i = 0; i < 16; ++i)
					put8bits(buffer, rr->rd_data.aaaa_record.addr[i]);
				break;
			case RR_CNAME:
				putcname(buffer, rr->rd_data.cname_record.name);
				break;
			case RR_NS:
				putcname(buffer, rr->rd_data.ns_record.name);
				break;
			case RR_SOA:
				putcname(buffer, rr->rd_data.soa_record.MName);   /* Author Name Server */
				putcname(buffer, rr->rd_data.soa_record.RName);  /* mail of DNS */
				put32bits(buffer, rr->rd_data.soa_record.serial);   /* serial */
				put32bits(buffer, rr->rd_data.soa_record.refresh); /* refresh */
				put32bits(buffer, rr->rd_data.soa_record.retry); /* retry */
				put32bits(buffer, rr->rd_data.soa_record.expire); /* expire */
				put32bits(buffer, rr->rd_data.soa_record.minimum); /* minimum */
				break;
			default:
				fprintf(stderr, "Unknown type %u. => Ignore resource record.\n", rr->type);
			return 1;
		}
		
		rr = rr->next;
	}
	return 0;
}

int Message_encode(struct Message* msg, uint8_t** buffer)
{
	struct Question* q;
	int rc;

	Message_encode_header(msg, buffer);

	q = msg->questions;
	while(q)
	{
		encode_domain_name(buffer, q->qName);
		put16bits(buffer, q->qType);
		put16bits(buffer, q->qClass);

		q = q->next;
	}

	rc = 0;
	rc |= encode_resource_records(msg->answers, buffer);
	rc |= encode_resource_records(msg->authorities, buffer);
	rc |= encode_resource_records(msg->additionals, buffer);

	return rc;
}

void free_resource_records(struct ResourceRecord* rr)
{
	struct ResourceRecord* next;

	while(rr) {
		next = rr->next;
		ResourceRecord_Free(rr);
		rr = next;
	}
}

void free_questions(struct Question* qq)
{
	struct Question* next;

	while(qq) {
		free(qq->qName);
		next = qq->next;
		free(qq);
		qq = next;
	}
}

void Message_init(struct Message *msg)
{
	memset(msg, 0, sizeof(struct Message));
	// leave most values intact for response
	msg->qr = 1; // this is a response
	msg->aa = 1; // this server is authoritative
	msg->ra = 0; // no recursion available
	msg->rcode = RT_NoError;
	msg->anCount = 0;
	msg->nsCount = 0;
	msg->arCount = 0;
}

void Message_free(struct Message *msg)
{
	free_questions(msg->questions);
	free_resource_records(msg->answers);
	free_resource_records(msg->authorities);
	free_resource_records(msg->additionals);
}

void Message_package(struct Message *msg, const uint8_t *data, size_t *len)
{
	uint8_t *p = (char *)data;
	if (Message_encode(msg, &p) != 0) 
	{
		*len = -1;
		return;
	}
	*len = ((char *)p - (char *)data);
}

void do_accept(evutil_socket_t sockfd, short event_type, void *arg)
{
	struct Message msg;
	int	sock = sockfd;
	int nbytes, rc, buflen;
	uint8_t buffer[BUF_SIZE];
	struct event_base *base = (struct event_base *)arg;
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(struct sockaddr_in);
	Message_init(&msg);
	nbytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, &addr_len);
	msg.cliaddr = client_addr.sin_addr;

	Message_unpackage(&msg, buffer, (size_t *)&nbytes);
	Message_resolve(&msg);
	Message_package(&msg, buffer, (size_t *)&buflen);

	sendto(sock, buffer, buflen, 0, (struct sockaddr*) &client_addr, addr_len);
	Message_free(&msg);

}

int main(int argc, char *argv[])
{
	socklen_t addr_len = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	int sock = 0, rc = 0;
	int port = 53;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		printf("Could not create socket: %s\n", strerror(errno));
		return 1;
	}

	evutil_make_socket_nonblocking(sock);
	rc = bind(sock, (struct sockaddr*) &addr, addr_len);
	if(rc != 0)
	{
		printf("Could not bind: %s\n", strerror(errno));
		return 1;
	}

	struct event_base *base = event_base_new();
	if (base == NULL) 
		return -1;

	//struct event *event = event_new(base, sock, EV_READ | EV_PERSIST, do_accept, (void*)base);  
	struct event *event = event_new(base, sock, EV_READ | EV_PERSIST, do_accept, (void*)base);  
	if (event == NULL) 
		return -1;

	event_add(event, NULL);
	event_base_dispatch(base);
#if 0
	int threads = atoi(argv[1]);
	int i = 0, ret = 0;
	pthread_t ths[threads];
	for (i = 0; i < threads; i++) 
	{
		struct event_base *base = event_base_new();
		if (base == NULL) 
			return -1;

		struct event *event = event_new(base, sock, EV_READ | EV_PERSIST, do_accept, (void*)base);  
		if (event == NULL) 
			return -1;

		event_add(event, NULL);
		event_base_dispatch(base);


		/* Optimize thread work on one cpu */
		pthread_attr_t attr;
		pthread_attr_init(&attr);
#if 0
		cpu_set_t cpu_info;
		CPU_ZERO(&cpu_info);
		CPU_SET(i, &cpu_info);

		if (pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpu_info) != 0) 
		{
			ret = pthread_create(&ths[i], NULL, (void *)event_base_dispatch, base);
		} 
		else 
		{
			ret = pthread_create(&ths[i], &attr, (void *)event_base_dispatch, base);
		}
		if (ret != 0) 

			return -1;
#endif
#if 0
		cpu_set_t cpu_info;
		CPU_ZERO(&cpu_info);
		CPU_SET(i, &cpu_info);
		pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpu_info);
#endif
		struct sched_param param;
		param.sched_priority = 99;
		pthread_attr_setschedparam (&attr, &param);
		pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
		pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
//		pthread_attr_setschedpolicy(&attr, SCHED_RR);
		ret = pthread_create(&ths[i], &attr, (void *)event_base_dispatch, base);
	}

	/* Wait for exit */
	for (i = 0; i < threads; i++) 
	{
		pthread_join(ths[i], NULL);
	}
#endif
	close(sock);

	return 0;
}
