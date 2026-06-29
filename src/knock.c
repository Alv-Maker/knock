/*
 *  knock.c
 *
 *  Copyright (c) 2004-2012 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (C) 2025 Alberto Novoa Gonzalez <angonzalez22@esei.uvigo.es>
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
#include <openssl/rand.h>

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
void *get_new_sequence(char *host, unsigned int port, char *topic);
unsigned short *parse_port_sequence(FILE *fp);
char *do_knocking(const char *hostname, unsigned short *sequence, char *message, int argc, char **argv, int old_portind);
char *read_line(FILE *fp);
char **slice_message(const char *message, int slices);
void free_sliced_message(char **slices, int count);
int replace_first_line(const char *filename, unsigned short newNumber);

int o_verbose = 0;
int o_udp = 0;
int o_delay = 0;
int o_ip = IP_DEFAULT;
char sequence_file[PATH_MAX] = "credential_0.txt"; /* default sequence file */

int main(int argc, char **argv)
{
	int sd;
	int opt, optidx = 1;

	char *ipname = malloc(256);
	int result;
	char *hostname;
	char *message = "hi from udp";
	static struct option opts[] =
		{
			{"verbose", no_argument, 0, 'v'},
			{"udp", no_argument, 0, 'u'},
			{"delay", required_argument, 0, 'd'},
			{"help", no_argument, 0, 'h'},
			{"version", no_argument, 0, 'V'},
			{"ipv4", no_argument, 0, '4'},
			{"ipv6", no_argument, 0, '6'},
			{"message", required_argument, 0, 'm'},
			{0, 0, 0, 0}};

	while ((opt = getopt_long(argc, argv, "vud:hV46m:f:", opts, &optidx)))
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
		case 'm':
			vprint("Using custom message: %s\n", optarg);
			message = optarg;
			break;
		case 'f':
			strncpy(sequence_file, optarg, sizeof(sequence_file) - 1);
			sequence_file[sizeof(sequence_file) - 1] = '\0';
			vprint("Using custom sequence file: %s\n", sequence_file);
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
	fp = fopen(sequence_file, "r");
	if (fp == NULL)
	{
		fprintf(stderr, "Failed to open %s for reading\n", sequence_file);
		exit(1);
	}
	unsigned short *sequence = parse_port_sequence(fp);
	//	char* anchor_topic =  read_line(fp);
	//	char *sailer_topic = read_line(fp);
	//	unsigned int mqtt_port = atoi(read_line(fp));
	fclose(fp);
	if (sequence == NULL)
	{
		fprintf(stderr, "Failed to parse port sequence\n");
		exit(1);
	}

	ipname = do_knocking(hostname, sequence, message, argc, argv, optind);

	// char *seq = get_new_sequence(ipname, mqtt_port, anchor_topic);
	// if (seq == NULL)
	//{
	//	fprintf(stderr, "Failed to get new sequence\n");
	//	exit(1);
	// }

	
	char *url = malloc(40);

	int is_ipv6 = strchr(ipname, ':') != NULL;
	if (is_ipv6)
	{
		vprint("Detected IPv6 address: %s\n", ipname);
		snprintf(url, 40, "ssl://[%s]:%d", ipname, 8883);
	}
	else
	{
		vprint("Detected IPv4 address: %s\n", ipname);
		snprintf(url, 40, "ssl://%s:%d", ipname, 8883);
	}

	// snprintf(url, 40, "ssl://%s:%d", ipname, 8883);

	
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
	printf("  -u, --udp            make all ports hits use UDP (default is TCP) -- not supported\n");
	printf("  -d, --delay <t>      wait <t> milliseconds between port hits\n");
	printf("  -4, --ipv4           Force usage of IPv4\n");
	printf("  -6, --ipv6           Force usage of IPv6\n");
	printf("  -v, --verbose        be verbose\n");
	printf("  -V, --version        display version\n");
	printf("  -h, --help           this help\n");
	printf("  -m  message to send in each knock (default is 'hi from udp')\n");
	printf("  -f,   file to read the sequence and topics from (default is 'credential_0.txt')\n");
	printf("\n");
	printf("example:  knock myserver.example.com 123 456 789\n");
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



unsigned short *parse_port_sequence(FILE *fp)
{
	if (fp == NULL)
	{
		fprintf(stderr, "Failed to open %s for reading\n", sequence_file);
		return NULL;
	}
	unsigned short sequenceLineNumber;
	unsigned short *sequence = malloc(32 * sizeof(unsigned short));

	fscanf(fp, "%hu", &sequenceLineNumber);

	fgetc(fp);

	// Avanzar hasta la línea sequenceLineNumber + 1
	unsigned int target = sequenceLineNumber - 1;
	vprint("Sequence line number: %hu, target line: %u\n", sequenceLineNumber, target);
	char buffer[256];

	for (unsigned int i = 0; i < target; i++)
	{
		if (fgets(buffer, sizeof(buffer), fp) == NULL)
			return NULL; // EOF o error
	}

	int i = 0;

	char nextToken, nextNextToken;
	while (i < 32)
	{
		
		if (fscanf(fp, "%hu", &sequence[i]) == 1)
			i++;
		else
			break;
		nextToken = fgetc(fp);
		if (nextToken == EOF || nextToken == '\n')
			break;
		nextNextToken = fgetc(fp);
		if (nextNextToken == EOF || nextNextToken == '\n' || nextNextToken == '\r')
			break;
		else
			ungetc(nextNextToken, fp);

		
	}

	return sequence;
}

char *read_line(FILE *fp)
{
	char *line = malloc(256);
	fscanf(fp, "%s", line);
	return line;
}

char *do_knocking(const char *hostname, unsigned short *sequence, char *message, int argc, char **argv, int old_portind)
{
	int sd;
	int result;
	struct addrinfo hints;
	struct addrinfo *infoptr;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = o_ip;
	char ipname[256];
	char *ip = malloc(256);

	/* Count actual sequence length */
	int sequence_len = 0;
	for (int j = 0; sequence[j] != 0; j++)
	{
		sequence_len++;
	}

	char **message_slices = slice_message(message, sequence_len - 2);
	if (message_slices == NULL)
	{
		fprintf(stderr, "Failed to slice message\n");
		return NULL;
	}

	/* Buffer para la secuencia antigua, declarado aquí para evitar corrupción de memoria */
	char payload_buffer[2048] = {0};

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
		sd = socket(infoptr->ai_family, SOCK_DGRAM, 0);
		if (sd == -1)
		{
			fprintf(stderr, "Cannot open socket\n");
			exit(1);
		}
		flags = fcntl(sd, F_GETFL, 0);
		fcntl(sd, F_SETFL, flags);

		/* extract ip as string (v4 or v6) */
		getnameinfo(infoptr->ai_addr, infoptr->ai_addrlen, ipname, sizeof(ipname), NULL, 0, NI_NUMERICHOST);

		/* connect or send UDP packet */

		/* MODIFICADO: En el segundo paquete (i == 1), enviar la secuencia antigua como payload */
		char *payload;
		int payload_len;

		if (i == 1)
		{
			/* Construir payload con los puertos antiguos (secuencia antigua) */
			memset(payload_buffer, 0, sizeof(payload_buffer));
			int buffer_pos = 0;

			for (int j = old_portind; j < argc; j++)
			{
				const char *port;
				char *ptr, *arg = strdup(argv[j]);

				if ((ptr = strchr(arg, ':')))
				{
					*ptr = '\0';
					port = arg;
					arg = ++ptr;
				}
				else
				{
					port = arg;
				}

				buffer_pos += snprintf(payload_buffer + buffer_pos, sizeof(payload_buffer) - buffer_pos, "%s ", port);
				free(arg);
			}

			/* Agregar marcador de fin de secuencia */
			snprintf(payload_buffer + buffer_pos, sizeof(payload_buffer) - buffer_pos, "END_SEQUENCE");

			payload = payload_buffer;
			payload_len = strlen(payload);

			vprint("Sending old sequence as payload: %s\n", payload);
		}
		else if (i > 1)
		{
			/* Enviar mensaje sliceado en los demás paquetes */
			if (message_slices[i - 2][0] != NULL)
			{
				payload = message_slices[i - 2];
				payload_len = strlen(payload);
			}
			else
			{
				payload = "END_MESSAGE";
				payload_len = strlen(payload);
			}
		}
		else
		{
			unsigned int random_num;
			if (RAND_bytes((unsigned char *)&random_num, sizeof(random_num)) != 1)
			{
				fprintf(stderr, "Failed to generate random bytes for payload\n");
				exit(1);
			}
			random_num = random_num % 32 + 1; // Generate random number 0-32
			payload_buffer[0] = '\0';		 // Clear the buffer
			snprintf(payload_buffer, sizeof(payload_buffer), "%u", random_num);
			payload = payload_buffer;
			payload_len = strlen(payload);
			vprint("Generated random payload: %s\n", payload);
			replace_first_line(sequence_file, (unsigned short)random_num);
		}

		vprint("hitting udp %s:%hu with message: %s\n", ipname, sequence[i], payload);

		sendto(sd, payload, payload_len, 0, infoptr->ai_addr, infoptr->ai_addrlen);

		close(sd);
		usleep(1000 * o_delay);
		freeaddrinfo(infoptr);

		usleep(1000 * o_delay); // Simulate delay between knocks
	}

	free_sliced_message(message_slices, sequence_len - 2);
	snprintf(ip, 256, "%s", ipname);
	return ip; // Return the last IP name used for knocking
}

char **slice_message(const char *message, int slices)
{
	if (slices <= 0)
	{
		return NULL;
	}

	int message_len = strlen(message);
	int slice_size = (message_len + slices - 1) / slices; // Calculate slice size
	char **message_slides = malloc(slices * sizeof(char *));
	if (message_slides == NULL)
	{
		fprintf(stderr, "Failed to allocate memory for message slides\n");
		return NULL;
	}

	for (int i = 0; i < slices; i++)
	{
		message_slides[i] = malloc(slice_size + 1); // Allocate memory for each slice
		if (message_slides[i] == NULL)
		{
			fprintf(stderr, "Failed to allocate memory for slice %d\n", i);
			free_sliced_message(message_slides, i);
			return NULL;
		}

		// Calculate how many characters are actually left to copy
		int offset = i * slice_size;
		int remaining = message_len - offset;

		if (remaining > 0)
		{
			// Copy only the characters that exist (not beyond end of string)
			int to_copy = remaining < slice_size ? remaining : slice_size;
			strncpy(message_slides[i], message + offset, to_copy);
			message_slides[i][to_copy] = NULL;
		}
		else
		{
			// No more characters, empty string
			message_slides[i][0] = NULL;
		}
	}

	return message_slides;
}

void free_sliced_message(char **slices, int count)
{
	if (slices == NULL)
	{
		return;
	}

	for (int i = 0; i < count; i++)
	{
		if (slices[i] != NULL)
		{
			free(slices[i]);
		}
	}
	free(slices);
}

int replace_first_line(const char *filename, unsigned short newNumber)
{
    FILE *in = fopen(filename, "r");
    if (!in) return -1;

    FILE *out = fopen("temp.txt", "w");
    if (!out) {
        fclose(in);
        return -1;
    }

    // Escribir la nueva primera línea
    fprintf(out, "%hu\n", newNumber);

    // Saltar la primera línea original
    char buffer[512];
    fgets(buffer, sizeof(buffer), in);

    // Copiar el resto del archivo
    while (fgets(buffer, sizeof(buffer), in))
        fputs(buffer, out);

    fclose(in);
    fclose(out);

    // Reemplazar archivo original
    rename("temp.txt", filename);

    return 0;
}

/* vim: set ts=2 sw=2 noet: */
