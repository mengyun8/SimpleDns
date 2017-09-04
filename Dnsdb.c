#include <string.h>
#include <stdlib.h>
#include "Dnsdb.h"

void Zone_init(Zone_t *zone)
{
	memset(zone, 0, sizeof(Zone_t));
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

int Dnsdb_lookup_origin(Dnsdb_t *db, const char *name, char *origin)
{
	struct list_head        *pos = NULL;
	Domain_t                *tmp = NULL;               
	int			labal = 0, hit = -1;	
	char			origin_buf[RRLEN] = {0};
	char			*p = NULL;
                                                      
	list_for_each(pos, &(db->domain.list))
	{
		tmp = list_entry(pos, Domain_t, list);
		if ((p = strstr(name, tmp->name)) != NULL)
		{
			if (labal == 0 || p - name < labal)
			{
				strcpy(origin_buf, tmp->name);
				labal = p - name;
				hit ++;
			}
		}
	}
	return hit;
}

int Domain_findzone(Domain_t *domain, const char *name, struct ResourceRecord  *rr)
{			
	struct list_head        *pos = NULL;
	Zone_t			*tmp = NULL;
	int			hit = -1;

	list_for_each(pos, &(domain->zone.list))
	{
		tmp = list_entry(pos, Zone_t, list);
		if (strcmp(name, tmp->name) == 0)
		{
			rr = tmp->rr;
			hit++;
		}
	}
	return hit;
}

int Dnsdb_lookup_record(Dnsdb_t *db, const char *origin, const char *name, struct ResourceRecord  *rr)
{
	struct list_head        *pos = NULL;
	Domain_t                *tmp = NULL;               
	int			labal = 0, hit = -1;	
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
                                                      
	list_for_each(pos, &(db->domain.list))
	{
		tmp = list_entry(pos, Domain_t, list);
		if (strcmp(origin, tmp->name) == 0)
		{
			return Domain_findzone(tmp, relativename, rr);
		}
	}
	return 0;
}

int Dnsdb_lookup(Dnsdb_t *db, const char *name, struct ResourceRecord  *rr)
{
	char	origin[RRLEN] = {0};
	if (Dnsdb_lookup_origin(db, name, origin) <= 0)
		return -1;
	
	return Dnsdb_lookup_record(db, origin, name, rr);
}

int Dnsdb_authority(Dnsdb_t *db, const char *name, struct ResourceRecord  *rr)
{
	char	origin[RRLEN] = {0};
	return 0;
}
