#include "dns.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <utility>

namespace SimpleDNS {
const static unsigned short DNS_UDP_PORT = 53;
const static std::string 	DNS_HOST_IP  = "114.114.114.114";

} /* end of namespace SimpleDNS */

int main(int argc, char* argv[]) {
	struct sockaddr_in addr;
	socklen_t addr_len	= sizeof(addr);
	int sockfd 			= 0;

	char buf[520];
	int buf_len = sizeof(buf);

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("create socket");
		exit(1);
	}

	bzero(&addr, addr_len);
	addr.sin_family 		= AF_INET;
	addr.sin_port			= htons(SimpleDNS::DNS_UDP_PORT);
	addr.sin_addr.s_addr 	= inet_addr(SimpleDNS::DNS_HOST_IP.c_str());

	bzero(buf, buf_len);
	const char* host = "www.google.com";
	if (argc > 1) {
		host = argv[1];
	}
	printf("DNSQUERY: %s\n", host);
	int len = SimpleDNS::BuildDnsQueryPacket(host, buf, 0, buf_len);

	if (len < 0) {
		printf("build dns query packet fail.");
		exit(1);
	} else {
		printf("DNS Query Pakcet(%d):\n", len);
		SimpleDNS::PrintBuffer(buf, len);
	}
	
	sendto(sockfd, buf, len, 0, (struct sockaddr *)&addr, addr_len);
	
	bzero(buf, buf_len);
	len = recvfrom(sockfd, buf, buf_len, 0, (struct sockaddr *)&addr, &addr_len);
	printf("DNS Answer Packet(%d):\n", len);

	SimpleDNS::PrintBuffer(buf, len);
	SimpleDNS::ParseDnsResponsePacket(buf,len);
	return 0;
}


namespace SimpleDNS {

std::string IPBin2Dec(const std::string& data) {
	if (data.size() < 4) {
		return "";
	}
	char buf[32] = {0};
	snprintf(buf, sizeof(buf), "%d.%d.%d.%d", 
	(unsigned char)data[0], (unsigned char)data[1], 
	(unsigned char)data[2], (unsigned char)data[3]);
	return buf;
}

char Char2Hex(unsigned char ch) {
	if (ch >= 0 && ch <= 9) {
		return ch + '0';
	}
	return ch + 'a' - 10;
}

void PrintBuffer(const char* buf, int len) {
	int width = 16;

	for (int i = 0; i < len; i++) {
		if (i%width == 0) {
			printf ("%02d    ", i/width);
		}
		char ch = ' ';
		if ((i+1) % width == 0) {
			ch = '\n';
		}
		unsigned char byte = buf[i];
		int hi = 0x0f & (byte >> 4);
		int lo = 0x0f & byte;
		
		printf("%c%c%c", Char2Hex(hi), Char2Hex(lo), ch);
	}
	printf("\n");
}

int ParseUnsignedInt(const char* buf, int pos, int end, unsigned int& value) {
	value = 0;
	value = (unsigned char)buf[pos++];
	value = (value << 8)|(unsigned char)buf[pos++];
	value = (value << 8)|(unsigned char)buf[pos++];
	value = (value << 8)|(unsigned char)buf[pos++];

	return pos;
}

int ParseUnsignedShort(const char* buf, int pos, int end, unsigned short& value) {
	value = 0;
	value = (unsigned char)buf[pos++];
	value = (value << 8)|(unsigned char)buf[pos++];
	return pos;
}

int ParseHost(const char* buf, int pos, int end, std::string& host) {
	if (buf == NULL) {
		return pos;
	}
	unsigned int limit = 0xc0;
	unsigned int len = (unsigned char)buf[pos++];
	while (len != 0 && !(len & limit)) {
		host.append(buf+pos, len);
		pos += len;
		len = (unsigned char)buf[pos++];
		if (len != 0) {
			host.append(".");
		}
	}
	if (len & limit) {
		unsigned int offset = ((limit ^ len) << 8) | (unsigned char)buf[pos++];
		ParseHost(buf, offset, end, host);
	}	
	return pos;
}

int ParseQuestionSection(const char* buf, int pos, int end, SimpleDNS::DnsQuestionSection& dns_question_section) {
	pos = ParseHost(buf, pos, end, dns_question_section.host);
	pos = ParseUnsignedShort(buf, pos, end, dns_question_section.query_type);
	pos = ParseUnsignedShort(buf, pos, end, dns_question_section.query_class);
	return pos; 
}

int ParseResourceRecord(const char* buf, int pos, int end, SimpleDNS::DnsResource& dns_resource) {
	if (buf == NULL) {
		return pos;
	}
	pos = ParseHost(buf, pos, end, dns_resource.host);
	pos = ParseUnsignedShort(buf, pos, end, dns_resource.domain_type);
	pos = ParseUnsignedShort(buf, pos, end, dns_resource.domain_class);
	pos = ParseUnsignedInt(buf, pos, end, dns_resource.ttl);
	pos = ParseUnsignedShort(buf, pos, end, dns_resource.data_len);
	dns_resource.data_pos = pos;
	pos += dns_resource.data_len;
	return pos;
}

int ParseDnsRecordDataField(const char* buf, int pos, int end, SimpleDNS::DnsResource& res) {
	unsigned short type = res.domain_type;
	if (type == 1) {
		res.data = IPBin2Dec(std::string(buf + res.data_pos, res.data_len));
	} else if (type == 2 || type == 5) {
		ParseHost(buf, res.data_pos, end, res.data);
	} else if (type == 28) {
		res.data = "IPV6 ADDR";
	} else {
		res.data = "OTHERS";
	}
	return 0;
}

int ParseDnsResponsePacket(const char* buf, int end) {
	if (buf == NULL) {
		return -1;
	}
	int pos = 0;
	// query transaction id
	unsigned short query_id = 0;
	query_id = buf[pos++];
	query_id = (query_id << 8) | buf[pos++];
	
	bool req_recursive = false;
	unsigned short opcode_info = 0;
	// |qr| opcode |aa|tc|rd|rd|
	pos = ParseUnsignedShort(buf, pos, end, opcode_info);
	if (opcode_info & 0x0f) {
		printf("dns ret code non-zero, ret = %d\n", opcode_info & 0x0f);
		return -1;
	}
	
	if (opcode_info&0x80) {
		printf("recursived response.\n");
	} else {
		printf("non-recursived response.\n");
	}
	unsigned short query_cnt = 0;
	pos = ParseUnsignedShort(buf, pos, end, query_cnt);

	printf ("response query_cnt = %d\n", query_cnt);

	unsigned short answer_cnt = 0;
	pos = ParseUnsignedShort(buf, pos, end, answer_cnt);
	printf("response answer_cnt = %d\n", answer_cnt);

	unsigned short authority_cnt = 0;
	pos = ParseUnsignedShort(buf, pos, end, authority_cnt);
	printf("response authority_cnt = %d\n", authority_cnt);

	unsigned short additional_cnt = 0;
	pos = ParseUnsignedShort(buf, pos, end, additional_cnt);
	printf("response addtional_cnt = %d\n", additional_cnt);

	//============query section=================
	for (int i = 0; i < query_cnt; i++) {
		SimpleDNS::DnsQuestionSection dns_question;
		pos = ParseQuestionSection(buf, pos, end, dns_question);
		printf("question section: host = %s, type = %2d, class = %2d\n", dns_question.host.c_str(), dns_question.query_type, dns_question.query_class);
	}

	//===========answer section=================
	printf("[  answer section   ]\n");
	for (int i = 0; i < answer_cnt; i++) {
		SimpleDNS::DnsResource res;
		pos = ParseResourceRecord(buf, pos, end, res);
		ParseDnsRecordDataField(buf, pos, end, res);
		printf("host = %s, type = %2d, class = %2d, ttl = %4u, dlen = %2d, data = %s\n",
		res.host.c_str(), res.domain_type, res.domain_class, res.ttl, res.data_len, res.data.c_str());
	}

	//==========authority section==============
	printf("[  authority section   ]\n");
	for (int i = 0; i < authority_cnt; i++) {
		SimpleDNS::DnsResource res;
		pos = ParseResourceRecord(buf, pos, end, res);
		ParseDnsRecordDataField(buf, pos, end, res);
		printf("host = %s, type = %2d, class = %2d, ttl = %4u, dlen = %2d, data = %s\n",
		res.host.c_str(), res.domain_type, res.domain_class, res.ttl, res.data_len, res.data.c_str());
	}

	//==========additional section=============
	printf("[  additional section   ]\n");
	for (int i = 0; i < additional_cnt; i++) {
		SimpleDNS::DnsResource res;
		pos = ParseResourceRecord(buf, pos, end, res);
		ParseDnsRecordDataField(buf, pos, end, res);
		printf("host = %s, type = %2d, class = %2d, ttl = %4u, dlen = %2d, data = %s\n",
		res.host.c_str(), res.domain_type, res.domain_class, res.ttl, res.data_len, res.data.c_str());
	}
	return 0;
}

int BuildDnsQueryPacket(const char* host, char* buf, int pos, int end) {
	if (buf == NULL || host == NULL) {
		return 0;
	}
	//==========header section===========
	// query transaction id
	unsigned short query_id = 0x1234;
	buf[pos++] = 0xff & (query_id>>8);
	buf[pos++] = 0xff & query_id;
	
	bool req_recursive = true;
	// |qr| opcode |aa|tc|rd|rd|
	buf[pos++] = req_recursive ? 0x01 : 0x00;
	// |ra|reseverd|rcode|
	buf[pos++] = 0x00;
	
	// query count
	unsigned short query_cnt = 0x0001;
	buf[pos++] = 0xff & (query_cnt>>8);
	buf[pos++] = 0xff & query_cnt;

	// ans rr = 0
	buf[pos++] = 0;
	buf[pos++] = 0;
	
	buf[pos++] = 0;
	buf[pos++] = 0;

	buf[pos++] = 0;
	buf[pos++] = 0;
	
	//==========query section========
	int 	cp 		= 0;
	char 	ch		= 0;
	char 	last 	= 0;
	int 	lp 		= pos++;
	while ((ch = host[cp++]) != '\0' && pos < end) {
		if (ch != '.') {
			buf[pos++] = ch;
			last = ch;
			continue;
		}
		int len = pos - lp -1;
		if (len <= 0 || len > 63) {
			printf("host name format invalid.\n");
			return -1;
		}
		buf[lp] = len;
		lp = pos++;
	}
	if (last == '.') {
		buf[lp]		= 0;
	} else { 
		buf[lp] 	= pos - lp - 1;
		buf[pos++]	= 0;
	}

	//==========query type==========
	unsigned short query_type = 0x0001;
	buf[pos++] = 0xff & (query_type >> 8);
	buf[pos++] = 0xff & query_type;
	
	//==========query class=========
	unsigned short query_class = 0x0001;
	buf[pos++] = 0xff & (query_class >> 8);
	buf[pos++] = 0xff & query_class;
	
	return pos;
}

}/* end of namespace SimpleDNS */
