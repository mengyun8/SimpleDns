#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "Dns.h"
#include "log.h"

void print_hex(uint8_t* buf, size_t len)
{
	int i;
	printf("%u bytes:\n", (unsigned int)len);
	for(i = 0; i < len; ++i)
		printf("%02x ", buf[i]);
	printf("\n");
}

void print_resource_record(struct ResourceRecord* rr)
{
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
				printf("Name Server Resource Record { name %s}",
					rd->ns_record.name
				);
				break;
			case RR_CNAME:
				printf("Canonical Name Resource Record { name %s}",
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

	while ((pos = (uint8_t*)strchr((char *)beg, '.')) != NULL)
	{
		len = pos - beg;
		buf[i] = len;
		i += 1;
		memcpy(buf+i, beg, len);
		i += len;

		beg = pos + 1;
	}
	len = (int)(strlen((char *)domain) - (beg - domain));

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
	uint8_t name[RRLEN];
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

	return strdup((char *)name);
}

// foo.bar.com => 3foo3bar3com0
void encode_domain_name(uint8_t** buffer, const uint8_t* domain)
{
	uint8_t* buf = *buffer;
	const uint8_t* beg = domain;
	const uint8_t* pos;
	int len = 0;
	int i = 0;

	while((pos = (uint8_t *)strchr((char *)beg, '.')) != NULL)
	{
		len = pos - beg;
		buf[i] = len;
		i += 1;
		memcpy(buf+i, beg, len);
		i += len;

		beg = pos + 1;
	}

	len = strlen((char *)domain) - (beg - domain);

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
	//char name[DOMAINLEN];
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
	//uint16_t opt_nsid;
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

struct ResourceRecord  *ResourceRecord_Create(const char *name, const char *origin, uint32_t type, uint32_t ttl, const char *rdata)
{
	struct ResourceRecord *tmp = NULL;
	tmp = malloc(sizeof(struct ResourceRecord));
	memset(tmp, 0, sizeof(struct ResourceRecord));
	tmp->name = strdup(name);
	tmp->origin = strdup(origin);
	tmp->class = 0x0001;
	tmp->type = type;
	tmp->ttl = ttl;
	tmp->next = NULL;

	switch (type)
	{
		case RR_A:
			tmp->rd_length = 4;
			if (inet_pton(AF_INET, rdata, (void *)&(tmp->rd_data.a_record.addr)) == 0)
			{
				log(LOG_INFO, "inet_pton: %s", strerror(errno));
			}
			break;
		case RR_AAAA:
			tmp->rd_length = 16;
			inet_pton(AF_INET6, rdata, (void *)&(tmp->rd_data.aaaa_record.addr));
			break;
		case RR_CNAME:
			tmp->rd_length = strlen(rdata) + 2;
			tmp->rd_data.cname_record.name = strdup(rdata);
			break;
		case RR_NS:
			tmp->rd_length = strlen(rdata) + 2;
			tmp->rd_data.ns_record.name = strdup(rdata);
			break;
		default:
			free(tmp);
			return NULL;
	}
	return tmp;
}

struct ResourceRecord  *ResourceRecord_Init(const char *name, uint32_t type)
{
	struct ResourceRecord *tmp = NULL;

	tmp = malloc(sizeof(struct ResourceRecord));
	memset(tmp, 0, sizeof(struct ResourceRecord));
	tmp->name = strdup(name);
	tmp->type = type;
	tmp->class = 0x0001;
	tmp->next = NULL;
	return tmp;
}

void ResourceRecord_Debug(struct ResourceRecord  *rr)
{
	if (rr->type == RR_A)
	{
		printf("ResourceRecord_Debug >> A %s %s\n", rr->name, inet_ntoa(rr->rd_data.a_record.addr));
	}
	else if (rr->type == RR_NS)
	{
		printf("ResourceRecord_Debug >> NS %s %s\n", rr->name, rr->rd_data.ns_record.name);
	}
	else if (rr->type == RR_CNAME)
	{
		printf("ResourceRecord_Debug >> CNAME %s %s\n", rr->name, rr->rd_data.cname_record.name);
	}
}

struct ResourceRecord  *ResourceRecord_Dump(struct ResourceRecord  *rr)
{
	int		i = 0;
	struct ResourceRecord *tmp = NULL;
	tmp = malloc(sizeof(struct ResourceRecord));
	memset(tmp, 0, sizeof(struct ResourceRecord));
	tmp->name = strdup(rr->name);
	tmp->origin = strdup(rr->origin);
	tmp->class = 0x0001;
	tmp->type = rr->type;
	tmp->ttl = rr->ttl;
	tmp->next = NULL;

//	ResourceRecord_Debug(rr);
	switch (rr->type)
	{
		case RR_A:
			tmp->rd_length = 4;
			tmp->rd_data.a_record.addr = rr->rd_data.a_record.addr;
			break;
		case RR_AAAA:
			tmp->rd_length = 16;
			for (i = 0; i < 16; i++)
			{
				tmp->rd_data.aaaa_record.addr[i] = rr->rd_data.aaaa_record.addr[i];
			}
			break;
		case RR_CNAME:
			tmp->rd_length = strlen(rr->rd_data.cname_record.name) + 2;
			tmp->rd_data.cname_record.name = strdup(rr->rd_data.cname_record.name);
			break;
		case RR_NS:
			tmp->rd_length = strlen(rr->rd_data.ns_record.name) + 2;
			tmp->rd_data.ns_record.name = strdup(rr->rd_data.ns_record.name);
			break;
		default:
			free(tmp);
			return NULL;
	}
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

void ResourceRecord_Clean(struct ResourceRecord  *rr)
{
	struct ResourceRecord  *tmp = rr;
	while (tmp)
	{
		ResourceRecord_Free(tmp);
		tmp = tmp->next;
	}
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
	struct ResourceRecord *new = NULL;
	struct ResourceRecord *tmp = NULL;
	tmp = msg->answers;

	new = ResourceRecord_Dump(rr);
	if (!tmp)
	{
		msg->answers = new;
	}
	else
	{
		while (tmp->next)
		{
			tmp = tmp->next;
		}
		tmp->next = new;
	}
	msg->anCount ++;
}

void ResourceRecord_add_Author(struct Message *msg, struct ResourceRecord* rr)
{
	struct ResourceRecord *new = NULL;
	struct ResourceRecord *tmp = NULL;
	tmp = msg->authorities;

	new = ResourceRecord_Dump(rr);
	if (!tmp)
	{
		msg->authorities = new;
	}
	else
	{
		while (tmp->next)
		{
			tmp = tmp->next;
		}
		tmp->next = new;
	}
	msg->nsCount ++;
}

int ResourceRecord_Add(struct Message *msg, struct ResourceRecord *rr)
{
	struct ResourceRecord *tmp = rr;

	while (tmp)
	{
		if (tmp->type == RR_SOA)
		{
			ResourceRecord_add_Author(msg, tmp);
		}
		else if (tmp->type == RR_A || tmp->type == RR_AAAA|| tmp->type == RR_NS || tmp->type == RR_CNAME)
		{
			ResourceRecord_Add_Answer(msg, tmp);
		}
		tmp = tmp->next;
	}
	return 0;
}

int  Message_Putrr(struct Message *msg, const char *name, uint32_t type, const char *rdata, uint32_t ttl)
{
	//int	rc = 0;
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

/* For every question in the message add a appropiate resource record
   in either section 'answers', 'authorities' or 'additionals'. */
int Message_resolve(struct Message *msg, env_t *env)
{
	struct ResourceRecord	*rr = NULL;
	struct Question		*q;
	char			qname[256] = {0};
	uint16_t		type = 0;
	uint16_t		class = 0;

	// leave most values intact for response
	msg->qr = 1; // this is a response
	msg->aa = 1; // this server is authoritative
	msg->ra = 0; // no recursion available
	msg->rcode = RT_NoError;
	//should already be 0
	msg->anCount = 0;
	msg->nsCount = 0;
	msg->arCount = 0;

	q = msg->questions;
	while (q)
	{
//		log(LOG_INFO, "Got Request from %s %s", q->qName, inet_ntoa(msg->cliaddr));
		strcpy(qname, q->qName);
		type = q->qType;
		class = q->qClass;
retry_find:
//		printf(" ---  Dnsdb lookup %s\n", qname);
#if 1
		rr = Dnsdb_lookup(&env->db, qname);
#else
		rr = ResourceRecord_Init(qname, type);
		if (!rr)
			return -1;

		if (ResourceRecord_Resolve(rr) < 0)
		{
			msg->rcode = RT_NotImp;
			break;
		}
#endif
		if (rr != NULL)
		{
			ResourceRecord_Add(msg, rr);
		}
		else
		{
			q = q->next;
			continue;
		}
		if (rr->type != type && rr->type == RR_CNAME)
		{
			strcpy(qname, rr->rd_data.cname_record.name);
			ResourceRecord_Clean(rr);
			goto retry_find;
		}
		else if (rr->type != type && rr->type == RR_NS)
		{
			strcpy(qname, rr->rd_data.ns_record.name);
			ResourceRecord_Clean(rr);
			goto retry_find;
		}
		ResourceRecord_Clean(rr);
		q = q->next;
	}
	return 0;
}

int encode_resource_records(struct ResourceRecord* rr, uint8_t** buffer)
{
	int i;
	uint32_t A_addr;
	//uint64_t AAAA_addr;
	while (rr)
	{
		/* Answer questions by attaching resource sections. */
		if (rr->type == RR_NS && strcmp(rr->name, "@") == 0)
		{
			putcname(buffer, (uint8_t *)rr->origin);
		}
		else
		{
			putcname(buffer, (uint8_t *)rr->name);
		}
		put16bits(buffer, (uint16_t)rr->type);
		put16bits(buffer, (uint16_t)rr->class);
		put32bits(buffer, (uint32_t)rr->ttl);
		put16bits(buffer, (uint16_t)rr->rd_length);
		
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
				putcname(buffer, (uint8_t *)rr->rd_data.cname_record.name);
				break;
			case RR_NS:
				putcname(buffer, (uint8_t *)rr->rd_data.ns_record.name);
				break;
			case RR_SOA:
				putcname(buffer, (uint8_t *)rr->rd_data.soa_record.MName);   /* Author Name Server */
				putcname(buffer, (uint8_t *)rr->rd_data.soa_record.RName);  /* mail of DNS */
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
		encode_domain_name(buffer, (uint8_t *)q->qName);
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

	while(rr) 
	{
		next = rr->next;
		ResourceRecord_Free(rr);
		rr = next;
	}
}

void free_questions(struct Question* qq)
{
	struct Question* next;

	while(qq) 
	{
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

void Message_package(struct Message *msg, const uint8_t *data, uint32_t *len)
{
	uint8_t *p = (uint8_t *)data;
	if (Message_encode(msg, &p) != 0) 
	{
		return;
	}
	*len = ((char *)p - (char *)data);
}


