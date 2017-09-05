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
#include <unistd.h>

#include <event2/event.h>
#include <event2/event_struct.h>

#include "conf.h"
#include "log.h"
#include "Dns.h"

#define BUF_SIZE 	1500
#define DOMAINLEN	256

void do_accept(evutil_socket_t sockfd, short event_type, void *arg)
{
	struct Message msg;
	int	sock = sockfd;
	int nbytes, buflen;
	uint8_t buffer[BUF_SIZE];
	//struct event_base *base = (struct event_base *)arg;
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(struct sockaddr_in);
	Message_init(&msg);
	nbytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *) &client_addr, &addr_len);
	msg.cliaddr = client_addr.sin_addr;

	Message_unpackage(&msg, buffer, (size_t *)&nbytes);
	Message_resolve(&msg);
	Message_package(&msg, buffer, (uint32_t *)&buflen);

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
