#ifndef __DNS_H
#define __DNS_H

#define RRLEN		256

/* These values are taken from RFC1537 */
#define DEFAULT_REFRESH     (60 * 60 * 8)
#define DEFAULT_RETRY       (60 * 60 * 2)
#define DEFAULT_EXPIRE      (60 * 60 * 24 * 7)
#define DEFAULT_MINIMUM     (60 * 60 * 24)

#define QR_MASK 	0x8000
#define OPCODE_MASK 	0x7800
#define AA_MASK 	0x0400
#define TC_MASK 	0x0200
#define RD_MASK 	0x0100
#define RA_MASK 	0x8000
#define RCODE_MASK 	0x000F


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

#endif
