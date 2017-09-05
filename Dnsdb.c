#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "Dns.h"
#include "Dnsdb.h"
#include "conf.h"
#include "log.h"

#define MAXLINE	1024

void Zone_init(Zone_t *zone)
{
	memset(zone, 0, sizeof(Zone_t));
	zone->rr = NULL;
	INIT_LIST_HEAD(&zone->list);
}

void Zone_free(Zone_t *zone)
{
	struct list_head        *pos = NULL, *p = NULL;
	Zone_t			*tmp = NULL;

	list_for_each_safe(pos, p, &zone->list)
	{
		tmp = list_entry(pos, Zone_t, list);
		list_del(&(tmp->list));
		free(tmp);
	}
}

void Domain_init(Domain_t *domain)
{
	memset(domain, 0, sizeof(Domain_t));
	Zone_init(&domain->zone);
	INIT_LIST_HEAD(&domain->list);
}

void Domain_free(Domain_t *domain)
{
	struct list_head        *pos = NULL, *p = NULL;
	Domain_t		*tmp = NULL;

	list_for_each_safe(pos, p, &domain->list)
	{
		tmp = list_entry(pos, Domain_t, list);
		list_del(&(tmp->list));
		Zone_free(&tmp->zone);	
		free(tmp);
	}
}

void Dnsdb_init(Dnsdb_t *db)
{
	memset(db, 0, sizeof(Dnsdb_t));
	Domain_init(&db->domain);
}

void Dnsdb_free(Dnsdb_t *db)
{
	Domain_free(&db->domain);
}

unsigned int Record_check(const char *type)
{
	if (strcmp(type, "A") == 0)
	{
		return RR_A;
	}
	else if (strcmp(type, "NS") == 0)
	{
		return RR_NS;
	}
	else if (strcmp(type, "CNAME") == 0)
	{
		return RR_CNAME;
	}
	else if (strcmp(type, "AAAA") == 0)
	{
		return RR_AAAA;
	}
	else if (strcmp(type, "SOA") == 0)
	{
		return RR_SOA;
	}
	else if (strcmp(type, "TXT") == 0)
	{
		return RR_TXT;
	}
	else if (strcmp(type, "MX") == 0)
	{
		return RR_MX;
	}
	return RR_UNKNOWN;
}

void Domain_Add(Domain_t *head, Domain_t *domain)
{
	list_add(&domain->list, &head->list);	
}

int Parse_zone_line(const char *confbuf, char *zone, char *file)
{
	int	i = 0;
	char	buf[MAXLINE] = {0};	
	char	*p = NULL, *str = NULL, *pstr;
	strcpy(buf, confbuf);
	
	for (p = buf; (str = strtok_r(p, " ", &pstr)) != NULL; p = NULL, i++)
	{
		if (i == 1)
		{
			strcpy(zone, str);
		}
		else if (i == 2)
		{
			strcpy(file, str);
		}
	}
	if (*zone == '\0' || *file == '\0')
		return -1;
	return 0;
}

int Zone_load(Zone_t *zone, const char *name, const char *zonebuf)
{
	int		i = 0, ret = 0;
	char		buf[MAXLINE] = {0};
	char		rname[RRLEN] = {0};
	char		rdata[RRLEN] = {0};
	long		ttl = 600;
	unsigned int	type = 0;
	val_t		val;
	val_t		*tmp = NULL;

	strncpy(buf, zonebuf, strlen(zonebuf) - 1);
	val_init(&val);
	if ((ret = buffer_get_key(buf, &val)) < 4)
	{
		return -1;
	}
	tmp = &val;
	while (tmp->next)
	{
		tmp = tmp->next; 
		if (i == 0)
		{
			if (tmp->val[strlen(tmp->val) - 1] == '.')
			{
				strncpy(rname, tmp->val, strlen(tmp->val) - 1);
			}
			else if (strcmp(tmp->val, "@") == 0)
			{
				strcpy(rname, tmp->val);
			}
			else
			{
				sprintf(rname, "%s.%s", tmp->val, name);
			}
		}
		else if (i == 1)
		{
			if (strcmp(tmp->val, "IN") != 0)
			{
				ttl = atoi(tmp->val);
				continue;
			}
		}
		else if (i == 2)
		{
			type = Record_check(tmp->val);	
		}
		else if (i == 3)
		{
			if ((type == RR_CNAME || type == RR_NS || type == RR_MX) && tmp->val[strlen(tmp->val) - 1] != '.')
			{
				sprintf(rdata, "%s.%s", tmp->val, name);
			}
			else if (tmp->val[strlen(tmp->val) - 1] != '.')
			{
				strcpy(rdata, tmp->val);
			}
			else
			{
				strncpy(rdata, tmp->val, strlen(tmp->val) - 1);
			}
		}
		i++;
	}

	val_free(&val);
	log(LOG_INFO, "Insert         name:%s type:%d data:[%s] ttl:%ld\n", rname, type, rdata, ttl);
	strcpy(zone->name, rname);
	zone->rr = ResourceRecord_Create(rname, type, ttl, rdata);
	return 0;
}

void Zone_Add(Zone_t *head, Zone_t *zone)
{
	list_add(&zone->list, &head->list);	
}

void Zone_debug(Zone_t *zone)
{
	struct list_head        *pos = NULL;
	Zone_t			*tmp = NULL;

	printf("Debug --- > zone : %s\n", zone->name);
                                                      
	list_for_each(pos, &(zone->list))
	{
		tmp = list_entry(pos, Zone_t, list);
		if (tmp->rr)
		{
			printf("--list \t\tZone: %s %d", tmp->name, tmp->rr->type);
		}
		else
		{
			printf("--list \t\tZone: %s ", tmp->name);
		}
		if (tmp->rr)
		{
			if (tmp->rr->type == RR_A)
			{
				printf("\t\t\t >> %s\n", inet_ntoa(tmp->rr->rd_data.a_record.addr));
			}
			else if (tmp->rr->type == RR_CNAME)
			{
				printf("\t\t\t >> %s\n", tmp->rr->rd_data.cname_record.name);
			}
			else if (tmp->rr->type == RR_NS)
			{
				printf("\t\t\t >> %s\n", tmp->rr->rd_data.ns_record.name);
			}
			else if (tmp->rr->type == RR_AAAA)
			{
				
			}
		}
	}
}

int Dnsdb_domain_load(Domain_t *domain, const char *name, const char *file)
{
	FILE	*fp = NULL;
	char	buf[MAXLINE] = {0};
	Zone_t	*zone = NULL;

	strcpy(domain->name, name);

	if ((fp = fopen(file, "r")) == NULL)
	{
		return -1;
	}

	while (fgets(buf, MAXLINE, fp))
	{
		if (*buf == '#' || *buf == ';')
		{
			memset(buf, 0, sizeof(buf));
			continue;
		}

		zone = (Zone_t *)malloc(sizeof(Zone_t));
		Zone_init(zone);
		if (Zone_load(zone, name, buf) < 0)
		{
			Zone_free(zone);
			memset(buf, 0, MAXLINE);
			continue;
		}
		Zone_Add(&domain->zone, zone);
		memset(buf, 0, MAXLINE);
	}
	fclose(fp);
	return 0;
}
void Domain_debug(Domain_t *domain)
{
	struct list_head        *pos = NULL;
	Domain_t                *tmp = NULL;
                                                      
	list_for_each(pos, &(domain->list))
	{
		tmp = list_entry(pos, Domain_t, list);
		printf("\tDomain: %s\n", tmp->name);
		Zone_debug(&tmp->zone);
	}
}

void Dnsdb_debug(Dnsdb_t *db)
{
	Domain_debug(&db->domain);
}

int Dnsdb_load(Dnsdb_t *db, const char *zone, const char *file)
{
	Domain_t	*domain = NULL;	
	domain = malloc(sizeof(Domain_t));	
	if (!domain)
		return -1;
	Domain_init(domain);

	if (Dnsdb_domain_load(domain, zone, file) < 0)
		return -1;

	Domain_Add(&db->domain, domain);

//	Dnsdb_debug(db);
	return 0;
}

int Dnsdb_lookup_origin(Dnsdb_t *db, const char *name, char *origin)
{
	struct list_head        *pos = NULL;
	Domain_t                *tmp = NULL;               
	int			labal = 0, hit = -1;	
	char			*p = NULL;
                                                      
	list_for_each(pos, &(db->domain.list))
	{
		tmp = list_entry(pos, Domain_t, list);
		if ((p = strstr(name, tmp->name)) != NULL)
		{
			if (labal == 0 || p - name < labal)
			{
				strcpy(origin, tmp->name);
				labal = p - name;
				hit ++;
			}
		}
	}
	return hit;
}

struct ResourceRecord  *Domain_findzone(Domain_t *domain, const char *name)
{			
	struct list_head        *pos = NULL;
	struct ResourceRecord  *rr = NULL;
	Zone_t			*tmp = NULL;

	list_for_each(pos, &(domain->zone.list))
	{
		tmp = list_entry(pos, Zone_t, list);
		if (strcmp(name, tmp->name) == 0 && tmp->rr)
		{
			rr = ResourceRecord_Dump(tmp->rr);
		}
	}
	return rr;
}

struct ResourceRecord  *Dnsdb_lookup_record(Dnsdb_t *db, const char *origin, const char *name)
{

	struct list_head        *pos = NULL;
	Domain_t                *tmp = NULL;               
#if 0
	char			relativename[RRLEN] = {0};
	char			*p = NULL;
	if ((p = strstr(name, origin)) == NULL)
	{
		return -1;
	}
	else
	{
		strncpy(relativename, name, p - name);
	}
#endif
                                                      
	list_for_each(pos, &(db->domain.list))
	{
		tmp = list_entry(pos, Domain_t, list);
		if (strcmp(origin, tmp->name) == 0)
		{
			return Domain_findzone(tmp, name);
		}
	}
	return NULL;
}

struct ResourceRecord  *Dnsdb_lookup(Dnsdb_t *db, const char *name)
{
	char	origin[RRLEN] = {0};
	if (Dnsdb_lookup_origin(db, name, origin) < 0)
		return NULL;
	
	return Dnsdb_lookup_record(db, origin, name);
}

int Dnsdb_authority(Dnsdb_t *db, const char *name, struct ResourceRecord  *rr)
{
	return 0;
}


