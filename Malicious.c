

/****************************************************
         This file contains code for generation of Malicious Node(WormHole) for networks running AODV in Layer3.
		 This works only for UDP and not for TCP.
		 
		 
		 The function fn_NetSim_AODV_MaliciousNode(NetSim_EVENTDETAILS*) 
		 return 1 when the deviceID is the malicious node which is mentioned in the if statement in the function definition.

		 
		 The function fn_NetSim_AODV_MaliciousRouteAddToCache(NetSim_EVENTDETAILS*)
		 adds the target address of the AODV RREQ it receives to its route cache so as to create a false route from 
		 the Source node to target node


		 The function fn_NetSim_AODV_MaliciousProcessSourceRouteOption(NetSim_EVENTDETAILS*)
		 Process the Data Packet received by the Malicious Node. It does not call the NetworkOut Event and destroys 
		 the packet, thus giving false acknowledge replies.

		 Code Flow - 
		 If The Node is a Malicious Node, Then when a Route Request is Received, the Function adds the route from itself 
		 to the target in the route cache and sends a false route reply.
		 When a malicious node receives a data packet, it gives acknowledge reply and frees the packet.
		  
		 


*****************************************************/


	/* Malicious Node */


#include "main.h"
#include "AODV.h"
#include "List.h"
#define MALICIOUS_NODE1 4

int fn_NetSim_AODV_MaliciousNode(NetSim_EVENTDETAILS* );
int fn_NetSim_AODV_MaliciousRouteAddToCache(NetSim_EVENTDETAILS*);
int fn_NetSim_AODV_MaliciousProcessSourceRouteOption(NetSim_EVENTDETAILS*);

#define WORMHOLE_NODE1 4
#define WORMHOLE_NODE2 10

// Utility: Check if the node is part of wormhole
int isWormholeNode(int id)
{
    return id == WORMHOLE_NODE1 || id == WORMHOLE_NODE2;
}

// Step 1: Intercept RREQ at one node and tunnel it to the other
int fn_NetSim_AODV_WormholeTunnelRREQ(NetSim_EVENTDETAILS* pstruEventDetails)
{
    if (pstruEventDetails->pPacket->nControlDataType != ctrlPacket_RREQ)
        return 0;

    if (pstruEventDetails->nDeviceId == WORMHOLE_NODE1)
    {
        // Tunnel the packet directly to WORMHOLE_NODE2
        NetSim_PACKET* tunneledPacket = fn_NetSim_Packet_CopyPacket(pstruEventDetails->pPacket);

        NetSim_EVENTDETAILS pevent;
        memcpy(&pevent, pstruEventDetails, sizeof(NetSim_EVENTDETAILS));
        pevent.nDeviceId = WORMHOLE_NODE2; // Redirect to other end
        pevent.nEventType = NETWORK_IN_EVENT;
        pevent.pPacket = tunneledPacket;
        pevent.dEventTime += 1.0; // Small delay

        fnpAddEvent(&pevent);

        // Drop the original packet
        fn_NetSim_Packet_FreePacket(pstruEventDetails->pPacket);
        return 1;
    }

    return 0;
}

