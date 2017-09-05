#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "Dnsdb.h"

#define MAXLINE	1024

void Zone_init(Zone_t *zone)
{
	memset(zone, 0, sizeof(Zone_t));
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

int Record_check(const char *type)
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
	return RR_A;
}

int Zone_load_line(Zone_t *head, const char *zone, const char *zonebuf)
{
	int		i = 0;
	char		buf[MAXLINE] = {0};
	char		name[RRLEN] = {0};
	char		rdata[RRLEN] = {0};
	long		ttl = 600;
	unsigned int	type;

	char		*p = NULL, *str = NULL, *pstr;
	strcpy(buf, zonebuf);

	for (p = buf; (str = strtok_r(p, " ", &pstr)) != NULL; p = NULL)
	{
		if (i == 0)
		{
			if (str[strlen(str) - 1] == '.')
			{
				strcpy(name, str);
			}
			else
			{
				sprintf(name, "%s.%s", str, zone);
			}
		}
		else if (i == 1)
		{
			if (strcmp(str, "IN") != 0)
			{
				ttl = atoi(str);
				continue;
			}
		}
		else if (i == 2)
		{
			type = Record_check(str);	
		}
		else if (i == 3)
		{
			strcpy(rdata, str);
		}
		i++;
	}

	return 0;
}

int Domain_load_zone(Domain_t *domain, const char *zonebuf)
{
	Zone_t	*zone = NULL;
	zone = malloc(sizeof(Zone_t));
	Zone_init(zone);
#if 0
	if (Zone_parse(zone, zonebuf) < 0)
		return -1;

#endif
//	Domain_add(domain, zone);
	return 0;
}

void Domain_add(Domain_t *head, Domain_t *domain)
{
	list_add(&head->list, &domain->list);	
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

int Zone_load(Zone_t *head, const char *zone, const char *file)
{
	FILE	*fp = NULL;
	char	buf[MAXLINE] = {0};

	strcpy(head->name, zone);

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
		Zone_load_line(head, zone, buf);
		memset(buf, 0, MAXLINE);
	}

	fclose(fp);
	return 0;
}

int Domain_load_line(Domain_t *head, const char *confbuf)
{
	char		zone[MAXLINE] = {0};
	char		file[MAXLINE] = {0};
	Domain_t	*domain = NULL;
	domain = malloc(sizeof(Domain_t));
	Domain_init(domain);
	Parse_zone_line(confbuf, zone, file);
	Zone_load(&domain->zone, zone, file);
	Domain_add(head, domain);
	return 0;
}

int Domain_load(Domain_t *head, const char *name, const char *file)
{
	FILE	*fp = NULL;
	char	buf[MAXLINE] = {0};

	strcpy(head->name, name);

	if ((fp = fopen(file, "r")) == NULL)
	{
		return -1;
	}

	while (fgets(buf, MAXLINE, fp))
	{
		if (strstr(buf, "zone:") != NULL)
		{
			Domain_load_line(head, buf);
		}
		memset(buf, 0, MAXLINE);
	}

	fclose(fp);
	return 0;
}

int Dnsdb_load(Dnsdb_t *db, const char *zone, const char *file)
{
	Domain_t	*domain = NULL;	
	domain = malloc(sizeof(Domain_t));	
	if (!domain)
		return -1;
	Domain_init(domain);

	return Domain_load(domain, zone, file);
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
	return 0;
}
