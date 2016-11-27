#include <string>

namespace SimpleDNS {

// NOT POD
typedef struct tagDnsQuestionSection {
	std::string host;
	unsigned short query_type;
	unsigned short query_class;
} DnsQuestionSection;

// NOT POD
typedef struct tagDnsResource {
	std::string 	host;
	unsigned short 	domain_type;
	unsigned short 	domain_class;
	unsigned int 	ttl;
	unsigned short	data_len;
	unsigned short	data_pos;
	std::string		data; // parsed
} DnsResource;

void PrintBuffer(const char* buf, int len);
int BuildDnsQueryPacket(const char* host, char* buf, int pos, int end);
int ParseDnsResponsePacket(const char* buf, int end);

} /* end fo the namespace SimpleDNS */
