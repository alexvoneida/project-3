#ifndef HEADER_H
#define HEADER_H 

#include <cstdio>
#include <cstring>
#include <string>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>


inline int LOG_LEVEL = 0;
#define TRACE   if (LOG_LEVEL > 5) { std::cout << "TRACE: "
#define DEBUG   if (LOG_LEVEL > 4) { std::cout << "DEBUG: "
#define INFO    if (LOG_LEVEL > 3) { std::cout << "INFO: "
#define WARNING if (LOG_LEVEL > 2) { std::cout << "WARNING: "
#define ERROR   if (LOG_LEVEL > 1) { std::cout << "ERROR: "
#define FATAL   if (LOG_LEVEL > 0) { std::cout << "FATAL: "
#define ENDL  " (" << __FILE__ << ":" << __LINE__ << ")" << std::endl; }

constexpr int PACKET_SIZE = 64;
constexpr int RECEIVE_BUFFER_SIZE = 1500;
constexpr int FIRST_TTL = 2;
constexpr int MAX_PROBES = 30;
constexpr int RESPONSE_TIMEOUT_SECONDS = 15;
constexpr int SELECT_INTERVAL_SECONDS = 5;

enum class ResponseType { EchoReply, TimeExceeded, Unrelated };

uint16_t checksum(unsigned short *buffer, int size);
void buildDatagram(char *packet, in_addr_t destination, uint16_t identifier);
void prepareProbe(char *packet, int ttl);
ResponseType classifyResponse(const char *buffer, size_t length, uint16_t identifier, uint16_t sequence);
bool awaitResponse(int recvFd, uint16_t identifier, int ttl);

#endif
