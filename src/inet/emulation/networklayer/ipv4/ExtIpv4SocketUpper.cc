//
// Copyright (C) OpenSim Ltd.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#include <omnetpp/platdep/sockets.h>

#ifndef  __linux__
#error The 'Network Emulation Support' feature currently works on Linux systems only
#else

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/ioctl.h>

#include "inet/common/ModuleAccess.h"
#include "inet/common/NetworkNamespaceContext.h"
#include "inet/common/ProtocolTag_m.h"
#include "inet/common/packet/Packet.h"
#include "inet/emulation/networklayer/ipv4/ExtIpv4SocketUpper.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/networklayer/common/InterfaceEntry.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "inet/networklayer/common/NextHopAddressTag_m.h"
#include "inet/common/IProtocolRegistrationListener.h"
#include "inet/networklayer/common/L3Tools.h"
#include "inet/transportlayer/common/L4Tools.h"
#include "inet/transportlayer/udp/UdpHeader_m.h"
#include "inet/transportlayer/udp/Udp.h"

namespace inet {

Define_Module(ExtIpv4SocketUpper);

ExtIpv4SocketUpper::~ExtIpv4SocketUpper()
{
    closeSocket();
}

void ExtIpv4SocketUpper::initialize(int stage)
{
    cSimpleModule::initialize(stage);
    if (stage == INITSTAGE_LOCAL) {
        device = par("device").stdstringValue();
        srcAddress = Ipv4Address(par("srcAddress").stringValue());
        packetNameFormat = par("packetNameFormat");
        rtScheduler = check_and_cast<RealTimeScheduler *>(getSimulation()->getScheduler());
        arp = getModuleFromPar<IArp>(par("arpModule"), this);
        ift = getModuleFromPar<IInterfaceTable>(par("interfaceTableModule"), this);
        registerService(Protocol::ipv4, nullptr, gate("lowerLayerIn"));
        registerProtocol(Protocol::ipv4, gate("lowerLayerOut"), nullptr);
        openSocket();
        numSent = numReceived = 0;
        WATCH(numSent);
        WATCH(numReceived);
    }
}

void ExtIpv4SocketUpper::handleMessage(cMessage *msg)
{
    Packet *packet = check_and_cast<Packet *>(msg);
    emit(packetReceivedFromLowerSignal, packet);
    if (packet->getTag<PacketProtocolTag>()->getProtocol() != &Protocol::ipv4)
        throw cRuntimeError("Invalid protocol");

    struct sockaddr_in ip_addr;
    ip_addr.sin_family = AF_INET;
#if !defined(linux) && !defined(__linux) && !defined(_WIN32)
    ip_addr.sin_len = sizeof(struct sockaddr_in);
#endif // if !defined(linux) && !defined(__linux) && !defined(_WIN32)
    ip_addr.sin_port = htons(0);

    auto ipv4Header = removeNetworkProtocolHeader<Ipv4Header>(packet);
    ipv4Header->setDestAddress(srcAddress);

    //correct udp crc:
    auto udpHeader = removeTransportProtocolHeader<UdpHeader>(packet);
    Udp::insertCrc(&Protocol::ipv4, ipv4Header->getSrcAddress(), ipv4Header->getDestAddress(), udpHeader, packet);

    insertTransportProtocolHeader(packet, Protocol::udp, udpHeader);
    insertNetworkProtocolHeader(packet, Protocol::ipv4, ipv4Header);

    auto bytesChunk = packet->peekDataAsBytes();
    uint8 buffer[1 << 16];
    size_t packetLength = bytesChunk->copyToBuffer(buffer, sizeof(buffer));
    ASSERT(packetLength == (size_t)packet->getByteLength());

    //int sent = ::send(fd, buffer, packetLength, 0);
    int sent = sendto(fd, buffer, packetLength, 0, (struct sockaddr *)&ip_addr, sizeof(ip_addr));
    if ((size_t)sent == packetLength) {
        EV << "Sent " << sent << " bytes packet.\n";
        numSent++;
    }
    else
        EV << "Sending packet FAILED! (sendto returned " << sent << " (" << strerror(errno) << ") instead of " << packetLength << ").\n";
    delete packet;
}

void ExtIpv4SocketUpper::refreshDisplay() const
{
    char buf[80];
    sprintf(buf, "snt:%d rcv:%d", numSent, numReceived);
    getDisplayString().setTagArg("t", 0, buf);
}

void ExtIpv4SocketUpper::finish()
{
    std::cout << getFullPath() << ": " << numSent << " packets sent, " << numReceived << " packets received\n";
    closeSocket();
}

void ExtIpv4SocketUpper::openSocket()
{
    NetworkNamespaceContext context(par("namespace"));
    fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (fd == INVALID_SOCKET)
        throw cRuntimeError("Cannot open socket");
    int hdrincl=1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &hdrincl, sizeof(hdrincl)) == -1)
        throw cRuntimeError("IP_HDRINCL");
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device.c_str() , device.length()) == -1)
        throw cRuntimeError("SO_BINDTODEVICE");
    if (gate("lowerLayerOut")->isConnected())
        rtScheduler->addCallback(fd, this);
}

void ExtIpv4SocketUpper::closeSocket()
{
    if (fd != INVALID_SOCKET) {
        if (gate("lowerLayerOut")->isConnected())
            rtScheduler->removeCallback(fd, this);
        close(fd);
        fd = INVALID_SOCKET;
    }
}

bool ExtIpv4SocketUpper::notify(int fd)
{
    //std::cout << "notify" << std::endl;
    Enter_Method_Silent();
    ASSERT(this->fd == fd);
    uint8_t buffer[1 << 16];
    memset(&buffer, 0, sizeof(buffer));
    // type of buffer in recvfrom(): win: char *, linux: void *
    int n = ::recv(fd, (char *)buffer, sizeof(buffer), 0);
    if (n < 0)
        throw cRuntimeError("Calling recvfrom failed: %d", n);
    auto data = makeShared<BytesChunk>(static_cast<const uint8_t *>(buffer), n);
    auto packet = new Packet(nullptr, data);
    packet->addTag<PacketProtocolTag>()->setProtocol(&Protocol::ipv4);
    //packet->addTag<DispatchProtocolReq>()->setProtocol(&Protocol::ipv4);
    packet->addTag<InterfaceReq>()->setInterfaceId(101);
    packet->setName(packetPrinter.printPacketToString(packet, packetNameFormat).c_str());

    const auto& ipv4Header = packet->peekAtFront<Ipv4Header>();
    EV_INFO << getFullPath() << ": Received a " << packet->getTotalLength() << " packet from " << ipv4Header->getSrcAddress() << " to " << ipv4Header->getDestAddress() << ".\n";
    if (ipv4Header->getSourceAddress().str() != srcAddress.str() || !ipv4Header->getDestinationAddress().matches(L3Address("10.0.0.0"), 24)) {
        EV_INFO << getFullPath() << ": drop packet src address is not machting: " << ipv4Header->getSourceAddress().str() << " != " << srcAddress.str() << ".\n";
        delete packet;
        return true;
    }
    packet->addTagIfAbsent<NextHopAddressReq>()->setNextHopAddress(ipv4Header->getDestAddress());
    const InterfaceEntry *ie = ift->getInterfaceById(packet->getTag<InterfaceReq>()->getInterfaceId());
    MacAddress macAddr = arp->resolveL3Address(ipv4Header->getDestAddress(), ie);
    packet->addTagIfAbsent<MacAddressReq>()->setDestAddress(macAddr);

    //emit(packetReceivedSignal, packet);
    send(packet, "lowerLayerOut");
    //emit(packetSentToLowerSignal, packet);
    numReceived++;
    return true;
}

} // namespace inet

#endif // __linux__

