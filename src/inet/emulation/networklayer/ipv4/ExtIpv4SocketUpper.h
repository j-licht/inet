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

#ifndef __INET_EXTIPV4SOCKET_H
#define __INET_EXTIPV4SOCKET_H

#include "inet/common/packet/printer/PacketPrinter.h"
#include "inet/common/scheduler/RealTimeScheduler.h"
#include "inet/networklayer/contract/IArp.h"

namespace inet {

class INET_API ExtIpv4SocketUpper : public cSimpleModule, public RealTimeScheduler::ICallback
{
  protected:
    // parameters
    std::string device;
    Ipv4Address srcAddress;
    L3Address destAddress;
    const char *packetNameFormat = nullptr;
    RealTimeScheduler *rtScheduler = nullptr;

    IArp *arp = nullptr;
    IInterfaceTable *ift = nullptr;

    // statistics
    int numSent = 0;
    int numReceived = 0;

    // state
    PacketPrinter packetPrinter;
    int fd = INVALID_SOCKET;

  protected:
    virtual int numInitStages() const override { return NUM_INIT_STAGES; }
    virtual void initialize(int stage) override;
    virtual void handleMessage(cMessage *msg) override;
    virtual void finish() override;
    virtual void refreshDisplay() const override;

    virtual void openSocket();
    virtual void closeSocket();

  public:
    virtual ~ExtIpv4SocketUpper();

    virtual bool notify(int fd) override;
};

} // namespace inet

#endif // ifndef __INET_EXTIPV4SOCKET_H

