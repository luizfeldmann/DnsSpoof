// ===================================================================================  //
//    This program is free software: you can redistribute it and/or modify              //
//    it under the terms of the GNU General Public License as published by              //
//    the Free Software Foundation, either version 3 of the License, or                 //
//    (at your option) any later version.                                               //
//                                                                                      //
//    This program is distributed in the hope that it will be useful,                   //
//    but WITHOUT ANY WARRANTY; without even the implied warranty of                    //
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                     //
//    GNU General Public License for more details.                                      //
//                                                                                      //
//    You should have received a copy of the GNU General Public License                 //
//    along with this program.  If not, see <https://www.gnu.org/licenses/>.            //
//                                                                                      //
//    Copyright: Luiz Gustavo Pfitscher e Feldmann, 2020                                //
// ===================================================================================  //

#include "zone_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

size_t getdelim(char **buf, size_t *bufsiz, int delimiter, FILE *fp)
{
	char *ptr, *eptr;


	if (*buf == NULL || *bufsiz == 0)
    {
		*bufsiz = BUFSIZ;
		if ((*buf = malloc(*bufsiz)) == NULL)
			return -1;
	}

	for (ptr = *buf, eptr = *buf + *bufsiz;;)
    {
		int c = fgetc(fp);
		if (c == -1)
		{
			if (feof(fp))
			{
				ssize_t diff = (ssize_t)(ptr - *buf);
				if (diff != 0)
				{
					*ptr = '\0';
					return diff;
				}
			}

			return -1;
		}

		*ptr++ = c;
		if (c == delimiter)
        {
			*ptr = '\0';
			return ptr - *buf;
		}

		if (ptr + 2 >= eptr)
        {
			char *nbuf;
			size_t nbufsiz = *bufsiz * 2;
			ssize_t d = ptr - *buf;
			if ((nbuf = realloc(*buf, nbufsiz)) == NULL)
				return -1;
			*buf = nbuf;
			*bufsiz = nbufsiz;
			eptr = nbuf + nbufsiz;
			ptr = nbuf + d;
		}
	}
}

void completeName(const char* origin, char* name)
{
    if (strcmp(name, "@") == 0)
        strcpy(name, origin);
    else if (name[strlen(name) - 1] != '.')
    {
        strcat(name, ".");
        strcat(name, origin);
    }
}

unsigned int read_zone_file(const char* filename, dns_answer_t** pointer_to_records)
{
    // open the file
    FILE* fp = fopen(filename, "rb+");
    if (fp == NULL)
    {
        fprintf(stderr, "\nError opening file %s: %d %s", filename, errno, strerror(errno));
        return 0;
    }

    unsigned int count_records = 0;
    dns_answer_t* record_collection = NULL;

    void addRecord(dns_answer_t new_rec)
    {
        dns_answer_t* new_collection = (dns_answer_t*)realloc(record_collection, sizeof(dns_answer_t) * (count_records + 1));
        if (new_collection == NULL)
            return; // allocation failed!

        record_collection = new_collection; // update old invalid pointer
        record_collection[count_records] = new_rec;
        count_records++;
    }

    // read the file
    char *line = NULL;
    size_t size = 0;

    uint32_t ttl = 60;
    char origin[256] = "";

    while(getdelim(&line, &size,'\n', fp) != EOF)
    {
        int read_ttl;
        char read_ttl_c;

        char read_name[255] = "";
        char read_argument[255] = "";
        int read_ip[4] = {0};

        if (sscanf(line, "$ORIGIN %s ", read_name) == 1)
        {
            strcpy(origin, read_name);
        }
        else if (sscanf(line, "$TTL %d%c", &read_ttl, &read_ttl_c) == 2)
        {
            ttl = read_ttl;
            switch (read_ttl_c)
            {
                case 'm': // minute
                    ttl *= 60;
                break;

                case 'h':
                case 'H': // hour
                    ttl *= 60*60;
                break;

                case 'd':
                case 'D': // day
                    ttl *= 60*60*24;
                break;

                case 'w': // week
                case 'W': // week
                    ttl *= 60*60*24*7;
                break;

                case 'M': // month
                    ttl *= 60*60*24*30;
                break;
            }
        }
        else if (sscanf(line, "%s IN A %u.%u.%u.%u", read_name, &read_ip[0], &read_ip[1], &read_ip[2], &read_ip[3]) == 5)
        {
            // get the full ip
            char ip_string[16];
            sprintf(ip_string, "%u.%u.%u.%u", read_ip[0], read_ip[1], read_ip[2], read_ip[3]);
            uint32_t ip_long = inet_addr(ip_string);

            // verify the ip is valid
            if (ip_long != 0xFFFFFFFF)
            {
                completeName(origin, read_name);

                dns_answer_t ans = (dns_answer_t) {
                    //.aname[QNAME_SIZE],
                    .atype = DNS_TYPE_A,
                    .aclass = DNS_CLASS_IN,
                    .ttl = ttl,
                    .rdlength = 4
                    //.rdata[RDATA_SIZE]
                };

                strcpy(ans.aname, read_name);
                memcpy(ans.rdata, &ip_long, ans.rdlength);

                addRecord(ans);
            }
        }
        else if (sscanf(line, "%s IN NS %s ", read_name, read_argument) == 2)
        {
            completeName(origin, read_name);
            completeName(origin, read_argument);

            dns_answer_t ans = (dns_answer_t) {
                //.aname[QNAME_SIZE],
                .atype = DNS_TYPE_NS,
                .aclass = DNS_CLASS_IN,
                .ttl = ttl,
                //.rdlength = len
                //.rdata[RDATA_SIZE]
            };

            strcpy(ans.aname, read_name);
            ans.rdlength = domain_plain_to_label(read_argument, (char*)ans.rdata);

            addRecord(ans);
        }
        else if (sscanf(line, "%s IN CNAME %s ", read_name, read_argument) == 2)
        {
            completeName(origin, read_name);
            completeName(origin, read_argument);

             dns_answer_t ans = (dns_answer_t) {
                //.aname[QNAME_SIZE],
                .atype = DNS_TYPE_CNAME,
                .aclass = DNS_CLASS_IN,
                .ttl = ttl,
                //.rdlength = len
                //.rdata[RDATA_SIZE]
            };

            strcpy(ans.aname, read_name);
            ans.rdlength = domain_plain_to_label(read_argument, (char*)ans.rdata);

            addRecord(ans);
        }
    }

    *pointer_to_records = record_collection;

    // cleanup
    free(line);
    fclose(fp);

    return count_records;
}

void print_records_collection(dns_answer_t* first, int count)
{
    for (int i = 0; i < count; i++)
    {
        printf("\n\nRECORD %d / %d:", i + 1, count);
        print_dns_answer(&first[i]);
    }
}

int find_next_dns_match(const char* domain, dns_answer_t* collection, unsigned int count, int previous)
{
    unsigned int record_index = (previous < 0) ? 0 : previous + 1;

    for (; record_index < count; record_index++)
    {
        //printf("\ntry match: %s\tto\t%s", collection[record_index].aname, domain);
        if (strcmp(collection[record_index].aname, domain) == 0)
            return record_index;
    }

    return -1;
}
