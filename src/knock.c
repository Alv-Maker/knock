/*
 *  knock.c
 *
 *  Copyright (c) 2004-2012 by Judd Vinet <jvinet@zeroflux.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#if defined(__FreeBSD__) || defined(__APPLE__)
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <resolv.h>
#include <getopt.h>
#include <fcntl.h>
#include <MQTTClient.h>

static char version[] = "0.9";

#define PROTO_TCP 1
#define PROTO_UDP 2

#define IP_DEFAULT AF_UNSPEC
#define IP_V4 AF_INET
#define IP_V6 AF_INET6

/* function prototypes */
void vprint(char *fmt, ...);
void ver();
void usage();
void *get_new_sequence(char *host, unsigned short port, char *topic);
unsigned short *parse_port_sequence(FILE *fp);
char *do_knocking(const char *hostname, unsigned short *sequence);
char* read_line(FILE *fp);

int o_verbose = 0;
int o_udp = 0;
int o_delay = 0;
int o_ip = IP_DEFAULT;

int main(int argc, char **argv)
{
	int sd;
	int opt, optidx = 1;

	char *ipname = malloc(256);
	int result;
	char *hostname;
	static struct option opts[] =
		{
			{"verbose", no_argument, 0, 'v'},
			{"udp", no_argument, 0, 'u'},
			{"delay", required_argument, 0, 'd'},
			{"help", no_argument, 0, 'h'},
			{"version", no_argument, 0, 'V'},
			{"ipv4", no_argument, 0, '4'},
			{"ipv6", no_argument, 0, '6'},
			{0, 0, 0, 0}};

	while ((opt = getopt_long(argc, argv, "vud:hV46", opts, &optidx)))
	{
		if (opt < 0)
		{
			break;
		}
		switch (opt)
		{
		case 0:
			break;
		case 'v':
			o_verbose = 1;
			break;
		case 'u':
			o_udp = 1;
			break;
		case 'd':
			o_delay = (int)atoi(optarg);
			break;
		case 'V':
			ver();
		case '4':
			o_ip = IP_V4;
			break;
		case '6':
			o_ip = IP_V6;
			break;
		case 'h': /* fallthrough */
		default:
			usage();
		}
	}
	if ((argc - optind) < 2)
	{
		usage();
	}

	if (o_delay < 0)
	{
		fprintf(stderr, "error: delay cannot be negative\n");
		exit(1);
	}

	/* prepare hints to select ipv4 or v6 if asked */

	hostname = argv[optind++];

	FILE *fp;
	fp = fopen("seq.conf", "r");
	if (fp == NULL)
	{
		fprintf(stderr, "Failed to open seq.conf for reading\n");
		exit(1);
	}
	unsigned short *sequence = parse_port_sequence(fp);
	char* anchor_topic =  read_line(fp);
	char *sailer_topic = read_line(fp);
	fclose(fp);
	if (sequence == NULL)
	{
		fprintf(stderr, "Failed to parse port sequence\n");
		exit(1);
	}

	ipname = do_knocking(hostname, sequence);

	char *seq = get_new_sequence(ipname, 1883, anchor_topic);
	if (seq == NULL)
	{
		fprintf(stderr, "Failed to get new sequence\n");
		exit(1);
	}

	MQTTClient client;
	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;

	char *url = malloc(40);

	snprintf(url, 40, "tcp://%s:%d", ipname, 1883);

	vprint("Connecting to MQTT broker at %s\n", url);

	int rc = MQTTClient_create(&client, url, "knock_client", MQTTCLIENT_PERSISTENCE_NONE, NULL);
	if (rc != MQTTCLIENT_SUCCESS)
	{
		fprintf(stderr, "Failed to create MQTT client, return code: %d\n", rc);
		free(url);
		exit(1);
	}

	sleep(2);

	MQTTClient_connect(client, &conn_opts);
	if (rc != MQTTCLIENT_SUCCESS)
	{
		fprintf(stderr, "Failed to connect MQTT client, return code: %d\n", rc);
		MQTTClient_destroy(&client);
		free(url);
		exit(1);
	}

	vprint("Connected to MQTT broker at %s\n", url);

	for (; optind < argc; optind++)
	{
		unsigned short proto = PROTO_TCP;
		const char *port;
		char *ptr, *arg = strdup(argv[optind]);
		vprint("Processing argument: %s\n", arg);

		if ((ptr = strchr(arg, ':')))
		{
			*ptr = '\0';
			port = arg;
			arg = ++ptr;

			proto = PROTO_TCP;
		}
		else
		{
			port = arg;
		}

		MQTTClient_publish(client, sailer_topic, strlen(port), port, 2, 0, NULL);
		MQTTClient_yield();
	}
	char *end = "END_SEQUENCE";
	MQTTClient_publish(client, sailer_topic, strlen(end), end, 2, 0, NULL);
	MQTTClient_yield();

	MQTTClient_disconnect(client, 1000);
	MQTTClient_destroy(&client);
	free(url);

	return (0);
}

void vprint(char *fmt, ...)
{
	va_list args;
	if (o_verbose)
	{
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
		fflush(stdout);
	}
}

void usage()
{
	printf("usage: knock [options] <host> <port[:proto]> [port[:proto]] ...\n");
	printf("options:\n");
	printf("  -u, --udp            make all ports hits use UDP (default is TCP)\n");
	printf("  -d, --delay <t>      wait <t> milliseconds between port hits\n");
	printf("  -4, --ipv4           Force usage of IPv4\n");
	printf("  -6, --ipv6           Force usage of IPv6\n");
	printf("  -v, --verbose        be verbose\n");
	printf("  -V, --version        display version\n");
	printf("  -h, --help           this help\n");
	printf("\n");
	printf("example:  knock myserver.example.com 123:tcp 456:udp 789:tcp\n");
	printf("\n");
	exit(1);
}

void ver()
{
	printf("knock %s\n", version);
	printf("Developed by: \n");
	printf("Copyright (C) 2025 Alberto Novoa Gonzalez <angonzalez22@esei.uvigo.es>\n");
	printf("Based on version 0.8 code developed by:\n");
	printf("Copyright (C) 2004-2012 Judd Vinet <jvinet@zeroflux.org>\n");

	exit(0);
}

void *get_new_sequence(char *host, unsigned short port, char *topic)
{
	MQTTClient client;
	FILE *fp;
	fp = fopen("seq.conf", "w");
	if (fp == NULL)
	{
		fprintf(stderr, "Failed to open seq.conf for writing\n");
		return NULL;
	}

	char url[40];
	snprintf(url, 40, "tcp://%s:%u", host, port);
	printf("Connecting to MQTT broker at %s\n", url);

	int rc = MQTTClient_create(&client, url, "sailer", MQTTCLIENT_PERSISTENCE_NONE, NULL);
	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;

	MQTTClient_connect(client, &conn_opts);
	if (rc != MQTTCLIENT_SUCCESS)
	{
		vprintf("Failed to connect MQTT client, return code: %d\n", rc);
		return NULL;
	}

	MQTTClient_subscribe(client, topic, 2);
	MQTTClient_message *msg = NULL;
	unsigned int sizeSequence = 0;

	int topic_len;
	printf("Waiting for new sequence...\n");

	char *received_topic = NULL;
	rc = MQTTClient_receive(client, &received_topic, &topic_len, &msg, 5000);
	if (rc != MQTTCLIENT_SUCCESS || msg == NULL || msg->payload == NULL)
	{
		vprint("Failed to receive first message, return code: %d\n", rc);
		MQTTClient_disconnect(client, 1000);
		MQTTClient_destroy(&client);
		return NULL;
	}

	vprint("Received payload: %s\n", msg->payload);

	sizeSequence = atoi((char *)msg->payload);
	vprint("Received sequence size: %d\n", sizeSequence);
	int *sequence = malloc(sizeSequence * sizeof(int));
	MQTTClient_freeMessage(&msg);
	if (received_topic)
	{
		MQTTClient_free(received_topic);
		received_topic = NULL;
	}
	for (int i = 0; i < sizeSequence; i++)
	{
		rc = MQTTClient_receive(client, &received_topic, &topic_len, &msg, 5000);
		if (rc != MQTTCLIENT_SUCCESS || msg == NULL)
		{
			fprintf(stderr, "Failed to receive message, return code: %d\n", rc);
			MQTTClient_disconnect(client, 1000);
			MQTTClient_destroy(&client);
			free(sequence);
			return NULL;
		}
		sequence[i] = atoi((char *)msg->payload);
		fprintf(fp, "%d\n", sequence[i]);

		vprint("Received port %i: %d\n", i, sequence[i]);
		MQTTClient_freeMessage(&msg);
		if (received_topic)
		{
			MQTTClient_free(received_topic);
			received_topic = NULL;
		}
	}
	fprintf(fp, "0\n"); // End of sequence marker
	rc = MQTTClient_receive(client, &received_topic, &topic_len, &msg, 5000);
	if (rc != MQTTCLIENT_SUCCESS || msg == NULL || msg->payload == NULL)
	{
		fprintf(stderr, "Failed to receive anchor topic, return code: %d\n", rc);
		free(sequence);
		MQTTClient_disconnect(client, 1000);
		MQTTClient_destroy(&client);
		fclose(fp);
		return NULL;
	}
	fprintf(fp, "%s\n", msg->payload);
	rc = MQTTClient_receive(client, &received_topic, &topic_len, &msg, 5000);
	if (rc != MQTTCLIENT_SUCCESS || msg == NULL || msg->payload == NULL)
	{
		fprintf(stderr, "Failed to receive sailer topic, return code: %d\n", rc);
		free(sequence);
		MQTTClient_disconnect(client, 1000);
		MQTTClient_destroy(&client);
		fclose(fp);
		return NULL;
	}
	fprintf(fp, "%s\n", (char *)msg->payload);
	MQTTClient_disconnect(client, 1000);
	MQTTClient_destroy(&client);
	fclose(fp);
	return sequence;
}

unsigned short *parse_port_sequence(FILE *fp)
{
	if (fp == NULL)
	{
		fprintf(stderr, "Failed to open seq.conf for reading\n");
		return NULL;
	}
	unsigned short *sequence = malloc(32 * sizeof(unsigned short));
	if (sequence == NULL)
	{
		fprintf(stderr, "Failed to allocate memory for sequence\n");
		return NULL;
	}

	short unsigned port;

	for (int i = 0; i < 32; i++)
	{
		if (fscanf(fp, "%hu", &port) != 1)
		{
			if (feof(fp))
			{
				break;
			}
			fprintf(stderr, "Failed to read port from seq.conf\n");
			free(sequence);
			return NULL;
		}
		if(port == 0)
		{
			break;
		}
		sequence[i] = port;
		vprint("Parsed port: %hu\n", sequence[i]);
	}
	return sequence;
}

char* read_line(FILE *fp)
{
	char *line = malloc(256);
	fscanf(fp, "%s", line);
	return line;
}

char* do_knocking(const char *hostname, unsigned short *sequence)
{
	int sd;
	int result;
	struct addrinfo hints;
	struct addrinfo *infoptr;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = o_ip;
	char ipname[256];
	char *ip = malloc(256);

	for (int i = 0; sequence[i] != 0; i++)
	{
		vprint("Knocking on port %hu of %s\n", sequence[i], hostname);
		// Here you would implement the actual knocking logic, e.g., sending packets
		// to the specified ports. This is a placeholder for demonstration purposes.

		/* get host and port based on hints */

		char portstr[6];
		snprintf(portstr, sizeof(portstr), "%hu", sequence[i]);
		result = getaddrinfo(hostname, portstr, &hints, &infoptr);
		if (result)
		{
			fprintf(stderr, "Failed to resolve hostname '%s' on port %hu\n", hostname, sequence[i]);
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
			exit(1);
		}
		/* create socket */

		int flags;
		sd = socket(infoptr->ai_family, SOCK_STREAM, 0);
		if (sd == -1)
		{
			fprintf(stderr, "Cannot open socket\n");
			exit(1);
		}
		flags = fcntl(sd, F_GETFL, 0);
		fcntl(sd, F_SETFL, flags | O_NONBLOCK);

		/* extract ip as string (v4 or v6) */
		getnameinfo(infoptr->ai_addr, infoptr->ai_addrlen, ipname, sizeof(ipname), NULL, 0, NI_NUMERICHOST);

		/* connect or send UDP packet */

		vprint("hitting tcp %s:%hu\n", ipname, sequence[i]);
		connect(sd, infoptr->ai_addr, infoptr->ai_addrlen);

		close(sd);
		usleep(1000 * o_delay);
		freeaddrinfo(infoptr);

		usleep(1000 * o_delay); // Simulate delay between knocks
	}
	snprintf(ip, 256, "%s", ipname);
	return ip; // Return the last IP name used for knocking
}

/* vim: set ts=2 sw=2 noet: */
