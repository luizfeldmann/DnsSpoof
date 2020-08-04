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

#ifndef _DNS_PROTOCOL_H_
#define _DNS_PROTOCOL_H_

#include <stdint.h>

// REFERENCES:
//  http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm
//  https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf
//  https://www.ietf.org/rfc/rfc1035.txt


//
//                                  1  1  1  1  1  1
//    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                       ID                      |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |QR|  Opcode   |AA|TC|RD|RA|   Z    |   RCODE   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   QDCOUNT                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   ANCOUNT                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   NSCOUNT                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   ARCOUNT                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#define QR_MASK     (1 << 15)
#define OP_MASK     (0x0F << 11)
#define FLAG_MASK   (0x0F << 7)
#define RC_MASK     0x0F

enum dns_flags {
    QR_QUERY            = 0 << 15,
    QR_RESPONSE         = 1 << 15,

    OP_QUERY            = 0 << 11, // standard query
    OP_IQUERY           = 1 << 11, // inverse query for reverse lookup (get name from given ip) - obsolete
    OP_STATUS           = 2 << 11, // Server status request
    OP_RESERVED         = 3 << 11, // not used
    OP_NOTIFY           = 4 << 11, // used by primary server to tell other servers certain zone data has changed
    OP_UPDATE           = 5 << 11, // dynamic dns - used to update records selectively

    FLAG_AA             = 1 << 10, // Authoritative Answer - this bit is only meaningful in responses, and specifies that the responding name server is an authority for the domain name in question section. You should use this bit to report whether or not the response you receive is authoritative.
    FLAG_TC             = 1 << 9,  // TrunCation - specifies that this message was truncated
    FLAG_RD             = 1 << 8,  // Recursion Desired - this bit directs the name server to pursue the query recursively
    FLAG_RA             = 1 << 7,  // this be is set or cleared in a response, and denotes whether recursive query support is available in the name server.

    RC_NOERROR          = 0,
    RC_FORMATERR        = 1, // Format error - The name server was unable to interpret the query.
    RC_SERVERFAILURE    = 2, // Server failure - The name server was unable to process this query due to a problem with the name server.
    RC_NAMEERROR        = 3, // Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
    RC_NOTIMPLEMENTED   = 4, // Not Implemented - The name server does not support the requested kind of query
    RC_REFUSED          = 5, // Refused - The name server refuses to perform the specified operation for policy reasons.

    RC_YXDOMAIN         = 6, // A name exists when it should not
    RC_YXRRSET          = 7, // A resource record set exists, but it shouldnt
    RC_NXRRSET          = 8, // A resource record set does not exist, but it should
    RC_NOTAUTH          = 9, // The server is not authoritative
    RC_NOTZONE          = 10, // Specified name not within specified zone
};

typedef struct dns_header
{
    uint16_t id;        // A 16-bit identification field generated by the device that creates the DNS query. It is copied by the server into the response, so it can be used by that device to match that query to the corresponding reply received from a DNS server
    uint16_t flags;

    uint16_t QDCount;   // Specifies the number of questions in the Question section of the message.
    uint16_t ANCount;   // Specifies the number of resource records in the Answer section of the message.

    uint16_t NSCount;   // Specifies the number of resource records in the Authority section of the message
    uint16_t ARCount;   // Specifies the number of resource records in the Additional section of the message.
} dns_header_t;


// A DNS question has the format:
//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                    QNAME                      /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QTYPE                      |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QCLASS                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

enum dns_type {
    DNS_TYPE_A      = 1,         // 1 // a host address
    DNS_TYPE_NS     = 2,         // 2 // an authoritative name server
    DNS_TYPE_MD     = 3,         // 3 // a mail destination (Obsolete - use MX)
    DNS_TYPE_MF     = 4,         // 4 // a mail forwarder (Obsolete - use MX)
    DNS_TYPE_CNAME  = 5,         // 5 // the canonical name for an alias
    DNS_TYPE_SOA    = 6,         // 6 // marks the start of a zone of authority
    DNS_TYPE_MB     = 7,         // 7 // a mailbox domain name (EXPERIMENTAL)
    DNS_TYPE_MG     = 8,         // 8 // a mail group member (EXPERIMENTAL)
    DNS_TYPE_MR     = 9,         // 9 // a mail rename domain name (EXPERIMENTAL)
    DNS_TYPE_NULL   = 10,        // 10 // a null RR (EXPERIMENTAL)
    DNS_TYPE_WKS    = 11,        // 11 // a well known service description
    DNS_TYPE_PTR    = 12,        // 12 // a domain name pointer
    DNS_TYPE_HINFO  = 13,        // 13 // host information
    DNS_TYPE_MINFO  = 14,        // 14 // mailbox or mail list information
    DNS_TYPE_MX     = 15,        // 15 // mail exchange
    DNS_TYPE_TXT    = 16,        // 16 // text strings
    DNS_TYPE_AAAA   = 28,        // 28 // ipv6 host address
};

enum dns_class {
    DNS_CLASS_IN    = 1, // the Internet
    DNS_CLASS_CS    = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    DNS_CLASS_CH    = 3, // the CHAOS class
    DNS_CLASS_HS    = 4, // Hesiod [Dyer 87]
    DNS_CLASS_ANY   = 255, // any class
};

#define QNAME_SIZE 255
typedef struct dns_question
{
    char qname[QNAME_SIZE]; // this data is parsed - pointers are resolved and label format is converted to plain text
    uint16_t qtype;     // A two octet code which specifies the type of the query
    uint16_t qclass;    // A two octet code that specifies the class of the query
} dns_question_t;

// A DNS answer has the format:
//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                                               /
// /                       NAME                    /
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                       TYPE                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                       CLASS                   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                       TTL                     |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                       RDLENGTH                |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
// /                       RDATA                   /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


#define RDATA_SIZE 255
typedef struct dns_answer {
    char aname[QNAME_SIZE]; // this data is parsed - pointers are resolved and label format is converted to plain text
    uint16_t atype;     // This field specifies the meaning of the data in the RDATA field
    uint16_t aclass;    // the class of the data in the RDATA field
    uint32_t ttl;       // The number of seconds the results can be cached
    uint16_t rdlength;  // The length of the RDATA field
    uint8_t rdata[RDATA_SIZE]; // this data is stored "as read from datagram" - no parsing at all
} dns_answer_t;


typedef struct dns_transaction {
    dns_header_t header;
    dns_question_t *questions;
    dns_answer_t *answers_an;
    dns_answer_t *answers_ns;
    dns_answer_t *answers_ar;
} dns_transaction_t;




int domain_plain_to_label(const char* name, char *label_buff);

dns_transaction_t* read_dns_transaction(const char* dgram, int length);
void print_dns_transaction(dns_transaction_t* tra);
void free_dns_transaction(dns_transaction_t* tra);
dns_transaction_t* create_dns_reply(dns_transaction_t* query);
void add_answer_to_dns_reply(dns_transaction_t* reply, dns_answer_t new_answer);
int write_dns_transaction(char* dgram, int buffer_length, dns_transaction_t* tra);

//char* read_dns_answer(const char* dgram_start, const char* answer_start, dns_answer_t* answer);
//char* write_dns_answer(char* position, dns_answer_t* answer);
void print_dns_answer(dns_answer_t* answer);

//char* read_dns_question(const char* dgram_start, const char* question_start, dns_question_t* question);
//char* write_dns_question(char* position, dns_question_t* question);
void print_dns_question(dns_question_t* question);

#endif // _DNS_PROTOCOL_H_
