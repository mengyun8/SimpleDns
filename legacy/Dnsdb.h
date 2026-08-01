#ifndef __DNSDB_H
#define __DNSDB_H

#include "list.h"
#include "Dns.h"

#define RRLEN	256

typedef struct Zone_type {
	char		name[RRLEN];
	struct ResourceRecord  *rr;
	struct list_head	list;
} Zone_t;

typedef struct Domain_type {
	char		name[RRLEN];	
	Zone_t		zone;
	struct list_head	list;
} Domain_t;

typedef struct Dnsdb_type {
	Domain_t	domain;	
} Dnsdb_t;

void Zone_init(Zone_t *zone);
void Zone_free(Zone_t *zone);

void Domain_init(Domain_t *domain);
void Domain_free(Domain_t *domain);

void Dnsdb_init(Dnsdb_t *db);
void Dnsdb_free(Dnsdb_t *db);
int  Dnsdb_load(Dnsdb_t *db, const char *zone, const char *file);
struct ResourceRecord  *Dnsdb_lookup(Dnsdb_t *db, const char *name);
int  Dnsdb_authority(Dnsdb_t *db, const char *name, struct ResourceRecord  *rr);

#endif
