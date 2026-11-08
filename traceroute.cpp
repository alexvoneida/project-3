#include "traceroute.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <system_error>
#include <sys/select.h>

// ****************************************************************************
// * Compute the Internet Checksum over an arbitrary buffer.
// * (written with the help of ChatGPT 3.5)
// ****************************************************************************
uint16_t checksum(unsigned short *buffer, int size) {
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }
    if (size == 1) {
        sum += *(unsigned char *) buffer;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}

// ****************************************************************************
// * Fill the packet with the parts of the IP and ICMP Echo Request headers
// * that stay the same for every probe. The kernel fills in the IP ID,
// * source address and IP checksum because we leave them zero.
// ****************************************************************************
void buildDatagram(char *packet, in_addr_t destination, uint16_t identifier) {
    memset(packet, 'A', PACKET_SIZE);

    auto *ip = reinterpret_cast<struct iphdr *>(packet);
    ip->version = 4;
    ip->ihl = sizeof(struct iphdr) / 4;
    ip->tos = 0;
    ip->tot_len = htons(PACKET_SIZE);
    ip->id = 0;
    ip->frag_off = 0;
    ip->ttl = 0;
    ip->protocol = IPPROTO_ICMP;
    ip->check = 0;
    ip->saddr = 0;
    ip->daddr = destination;

    auto *icmp = reinterpret_cast<struct icmphdr *>(packet + sizeof(struct iphdr));
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->checksum = 0;
    icmp->un.echo.id = htons(identifier);
    icmp->un.echo.sequence = 0;
}

// ****************************************************************************
// * Set the TTL for the next probe. The TTL doubles as the ICMP sequence
// * number so responses can be matched to the probe that caused them.
// ****************************************************************************
void prepareProbe(char *packet, int ttl) {
    auto *ip = reinterpret_cast<struct iphdr *>(packet);
    ip->ttl = static_cast<uint8_t>(ttl);

    auto *icmp = reinterpret_cast<struct icmphdr *>(packet + sizeof(struct iphdr));
    icmp->un.echo.sequence = htons(static_cast<uint16_t>(ttl));
    icmp->checksum = 0;
    icmp->checksum = checksum(reinterpret_cast<unsigned short *>(icmp), PACKET_SIZE - sizeof(struct iphdr));
    TRACE << "ICMP checksum = 0x" << std::hex << ntohs(icmp->checksum) << std::dec << ENDL;
}

// ****************************************************************************
// * The raw ICMP socket delivers every ICMP message the host receives, so
// * only accept an Echo Reply, or a TTL Exceeded that quotes our Echo
// * Request, carrying our identifier and the sequence number of this probe.
// ****************************************************************************
ResponseType classifyResponse(const char *buffer, size_t length, uint16_t identifier, uint16_t sequence) {
    const auto *outerIp = reinterpret_cast<const struct iphdr *>(buffer);
    if (length < sizeof(struct iphdr) || outerIp->ihl < 5) {
        return ResponseType::Unrelated;
    }
    size_t outerHeaderLength = outerIp->ihl * 4;
    if (length < outerHeaderLength + sizeof(struct icmphdr)) {
        return ResponseType::Unrelated;
    }
    const auto *icmp = reinterpret_cast<const struct icmphdr *>(buffer + outerHeaderLength);

    if (icmp->type == ICMP_ECHOREPLY) {
        bool matches = ntohs(icmp->un.echo.id) == identifier && ntohs(icmp->un.echo.sequence) == sequence;
        return matches ? ResponseType::EchoReply : ResponseType::Unrelated;
    }

    if (icmp->type == ICMP_TIME_EXCEEDED && icmp->code == ICMP_EXC_TTL) {
        // The router copies our original IP header and the start of our ICMP header after its own ICMP header.
        const char *quoted = buffer + outerHeaderLength + sizeof(struct icmphdr);
        size_t quotedLength = length - outerHeaderLength - sizeof(struct icmphdr);
        if (quotedLength < sizeof(struct iphdr)) {
            return ResponseType::Unrelated;
        }
        const auto *quotedIp = reinterpret_cast<const struct iphdr *>(quoted);
        if (quotedIp->ihl < 5 || quotedIp->protocol != IPPROTO_ICMP) {
            return ResponseType::Unrelated;
        }
        size_t quotedHeaderLength = quotedIp->ihl * 4;
        if (quotedLength < quotedHeaderLength + sizeof(struct icmphdr)) {
            return ResponseType::Unrelated;
        }
        const auto *quotedIcmp = reinterpret_cast<const struct icmphdr *>(quoted + quotedHeaderLength);
        bool matches = quotedIcmp->type == ICMP_ECHO
                       && ntohs(quotedIcmp->un.echo.id) == identifier
                       && ntohs(quotedIcmp->un.echo.sequence) == sequence;
        return matches ? ResponseType::TimeExceeded : ResponseType::Unrelated;
    }

    return ResponseType::Unrelated;
}

// ****************************************************************************
// * Wait up to RESPONSE_TIMEOUT_SECONDS for a response to the probe sent with
// * the given TTL and print the result. Returns true if the destination
// * answered with an Echo Reply.
// ****************************************************************************
bool awaitResponse(int recvFd, uint16_t identifier, int ttl) {
    using std::chrono::steady_clock;
    const auto deadline = steady_clock::now() + std::chrono::seconds(RESPONSE_TIMEOUT_SECONDS);
    alignas(struct iphdr) char buffer[RECEIVE_BUFFER_SIZE];

    while (true) {
        auto remaining = deadline - steady_clock::now();
        if (remaining <= steady_clock::duration::zero()) {
            std::cout << "No response with TTL of " << ttl << std::endl;
            return false;
        }

        auto wait = std::chrono::duration_cast<std::chrono::microseconds>(
            std::min<steady_clock::duration>(remaining, std::chrono::seconds(SELECT_INTERVAL_SECONDS)));
        struct timeval timeout;
        timeout.tv_sec = wait.count() / 1000000;
        timeout.tv_usec = wait.count() % 1000000;

        fd_set readFdSet;
        FD_ZERO(&readFdSet);
        FD_SET(recvFd, &readFdSet);

        DEBUG << "Waiting up to " << wait.count() / 1000000.0 << " seconds for data to become available" << ENDL;
        int selectReturned = select(recvFd + 1, &readFdSet, nullptr, nullptr, &timeout);
        if (selectReturned < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::generic_category(), "select");
        }
        DEBUG << "selectReturned = " << selectReturned << ENDL;
        if (!FD_ISSET(recvFd, &readFdSet)) {
            continue;
        }

        struct sockaddr_in senderAddress;
        socklen_t addressLength = sizeof(senderAddress);
        DEBUG << "Calling recvfrom() to read an ICMP message" << ENDL;
        ssize_t received = recvfrom(recvFd, buffer, sizeof(buffer), 0,
                                    reinterpret_cast<struct sockaddr *>(&senderAddress), &addressLength);
        if (received < 0) {
            throw std::system_error(errno, std::generic_category(), "recvfrom");
        }

        char senderIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &senderAddress.sin_addr, senderIP, sizeof(senderIP));
        DEBUG << "Received " << received << " bytes from " << senderIP << ENDL;

        switch (classifyResponse(buffer, static_cast<size_t>(received), identifier, static_cast<uint16_t>(ttl))) {
        case ResponseType::EchoReply:
            std::cout << "TTL " << ttl << ": " << senderIP << " (Echo Reply, destination reached)" << std::endl;
            return true;
        case ResponseType::TimeExceeded:
            std::cout << "TTL " << ttl << ": " << senderIP << std::endl;
            return false;
        case ResponseType::Unrelated:
            DEBUG << "Ignoring ICMP message from " << senderIP << " that does not match this probe" << ENDL;
            break;
        }
    }
}


int main (int argc, char *argv[]) {
  std::string destIP;

  // ********************************************************************
  // * Process the command line arguments
  // ********************************************************************
  int opt = 0;
  while ((opt = getopt(argc,argv,"t:d:")) != -1) {

    switch (opt) {
    case 't':
      destIP = optarg;
      break;
    case 'd':
      try {
        LOG_LEVEL = std::stoi(optarg);
      } catch (const std::exception &) {
        std::cerr << "Debug level must be an integer" << std::endl;
        exit(EXIT_FAILURE);
      }
      break;
    case ':':
    case '?':
    default:
      std::cerr << "useage: " << argv[0] << " -t [target ip] -d [Debug Level]" << std::endl;
      exit(EXIT_FAILURE);
    }
  }

  if (destIP.empty()) {
    std::cerr << "useage: " << argv[0] << " -t [target ip] -d [Debug Level]" << std::endl;
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in destAddress;
  memset(&destAddress, 0, sizeof(destAddress));
  destAddress.sin_family = AF_INET;
  if (inet_pton(AF_INET, destIP.c_str(), &destAddress.sin_addr) != 1) {
    std::cerr << "Invalid destination IP address: " << destIP << std::endl;
    exit(EXIT_FAILURE);
  }
  DEBUG << "Destination IP: " << destIP << ", debug level: " << LOG_LEVEL << ENDL;

  // ICMP identifiers are 16 bits, so truncating the PID is expected.
  const uint16_t identifier = static_cast<uint16_t>(getpid() & 0xFFFF);
  alignas(struct iphdr) char packet[PACKET_SIZE];
  buildDatagram(packet, destAddress.sin_addr.s_addr, identifier);
  DEBUG << "Built Echo Request datagram with identifier " << identifier << ENDL;

  int sendFd = -1;
  int recvFd = -1;
  int exitCode = EXIT_SUCCESS;
  try {
    DEBUG << "Creating raw socket with protocol IPPROTO_RAW for sending" << ENDL;
    if ((sendFd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) {
      throw std::system_error(errno, std::generic_category(), "socket (are you running with sudo?)");
    }
    DEBUG << "Creating raw socket with protocol IPPROTO_ICMP for receiving" << ENDL;
    if ((recvFd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
      throw std::system_error(errno, std::generic_category(), "socket (are you running with sudo?)");
    }

    bool reachedDestination = false;
    for (int probe = 0; probe < MAX_PROBES && !reachedDestination; ++probe) {
      int ttl = FIRST_TTL + probe;
      prepareProbe(packet, ttl);

      DEBUG << "Sending Echo Request with TTL " << ttl << ENDL;
      if (sendto(sendFd, packet, PACKET_SIZE, 0,
                 reinterpret_cast<struct sockaddr *>(&destAddress), sizeof(destAddress)) == -1) {
        throw std::system_error(errno, std::generic_category(), "sendto");
      }

      reachedDestination = awaitResponse(recvFd, identifier, ttl);
    }

    if (!reachedDestination) {
      std::cout << "Did not reach " << destIP << " after " << MAX_PROBES << " probes" << std::endl;
    }
  } catch (const std::system_error &error) {
    std::cerr << error.what() << std::endl;
    exitCode = EXIT_FAILURE;
  }

  if (sendFd != -1) {
    close(sendFd);
  }
  if (recvFd != -1) {
    close(recvFd);
  }
  return exitCode;
}
