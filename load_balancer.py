from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str, str_to_dpid
from pox.lib.util import str_to_bool
import time
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ethernet, ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.revent import *
import random



log = core.getLogger()

# We don't want to flood immediately when a switch connects.
# Can be overriden on commandline.
_flood_delay = 0
HOST_NUMBER = 12

class LoadBalancerSwitch (object):

  def __init__ (self, connection):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection

    self.mac = EthAddr("00:00:00:00:00:" + str(HOST_NUMBER+1))
    self.ip = IPAddr("10.0.0." + str(HOST_NUMBER+1))
    # self.clientsMacs = [EthAddr("00:00:00:00:00:" + str(x)) for x in  range(1,HOST_NUMBER/2 +1) ]
    # self.serversMacs = [EthAddr("00:00:00:00:00:" + str(x)) for x in  range(HOST_NUMBER/2 +1,HOST_NUMBER +1) ]
    self.clientMacs = {}
    self.serverMacs = {}
    self.clientsIps = [IPAddr("10.0.0." + str(x)) for x in  range(1,HOST_NUMBER/2 +1) ]
    self.serversIps = [IPAddr("10.0.0." + str(x)) for x in  range(HOST_NUMBER/2 +1,HOST_NUMBER +1) ]
    self.ports = {}
    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    # We just use this to know when to log a helpful message
    self.hold_down_expired = _flood_delay == 0

    log.debug("Initializing Load Balancer")
    log.debug("Clients")
    log.debug(self.clientsIps)
    log.debug("Servers")
    log.debug(self.serversIps)

  def _handle_PacketIn (self, event):
    """
    Handle packet in messages from the switch to implement above algorithm.
    

    To behave as a transparent proxy between the clients and the servers
    the load balancer has to perform the following tasks:

    1. Reply client ARP requests with the fake MAC from the switch/frontend/load-balancer when clients 
        search for the MAC of the switch/frontend IP. Please save the information of the ARP request; namely,
        source MAC of the client and switch input port of the ARP request
        packet, so that when the load balancer has to direct flows to the
        clients, it will already know the address and the output port to forward the packages.
    
    2. Reply pool servers ARP request to client IPs with messaged ARP responses. The responses will contain 
        the fake MAC address associated with the load balancer. Note that by now, the load balancer
        should already know the real MAC address of the client.

    3. The load balancer should forward flows from the clients towards
        the servers using the following balancing approaches: random and
        round-robin. All packages received by the pool servers will have
        the fake MAC address of the load balancer and the IP of the client
        unmodified.

    4. Forward the packages from the pool servers to the clients after updating the source IP and MAC 
        addresses from that of the pool servers
        to the addresses of the load balancer. Clients should never know
        about the existence of the pool servers and cannot see any package
        from them. In other words, the load balancer will be completely
        transparent to them.

    """

    log.info("PACKET_IN")
    inport = event.port
    packet = event.parsed

    def select_server():
      return 0
      # return random.randint(0,5)

    def find_client_mac_by_ip(ip):
      return self.clientsMacs[self.clientsIps.index(ip)]

    def find_server_mac_by_ip(ip):
      return self.serversMacs[self.serversIps.index(ip)]
    """
    if arp request
        we dont know the destination
        select the destination, and send arp to search for port and mac
        now that we know, we make the flow mod that make this conexion possible 
          from h1 to h7 for example, and viceversa
        reply an arp response with fake ip
    else if icmp request

    """
    if packet.type == packet.ARP_TYPE:
        log.info("packet.ARP_TYPE == true")
        if packet.payload.opcode == arp.REQUEST:
            log.info("arp.REQUEST == true")
            a = packet.next
            self.ports[a.hwsrc] = inport
            log.info("self.ports")
            log.info(self.ports)
            if a.hwsrc in self.clientsMacs:
              selectedServer = select_server()
              a.hwsrc = self.mac
              a.hwdst = self.serversMacs[selectedServer]
              a.protodst = self.serversIps[selectedServer]
              e = ethernet(type=ethernet.ARP_TYPE, src=self.mac, dst=ETHER_BROADCAST)
              e.set_payload(a)
              log.debug("%s requesting ARP to %s" % (a.protosrc, a.protodst))
              msg = of.ofp_packet_out()
              msg.data = e.pack()
              msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
              msg.in_port = inport
              event.connection.send(msg)
              return
            elif a.hwsrc in self.serversMacs:
              log.debug("WARNING: Receiving an ARP request from a server!!")
              # a.hwdst = a.hwsrc
              # a.hwsrc = self.mac
              # a.opcode = arp.REPLY
              # a.protodst = a.protosrc
              # a.protosrc = self.ip
              # e = ethernet(type=ethernet.ARP_TYPE, src=self.mac, dst=a.hwdst)
              # e.set_payload(a)
              # log.debug("%s replying ARP to %s" % (self.mac, a.protodst))
              # msg = of.ofp_packet_out()
              # msg.data = e.pack()
              # msg.actions.append(of.ofp_action_output(port = inport))
              # msg.in_port = inport
              # event.connection.send(msg)
              return

            #send this packet to the switch
            #see section below on this topic
        elif packet.payload.opcode == arp.REPLY:
            log.info("arp.REPLY == true")
            a = packet.next
            self.ports[a.hwsrc] = inport
            log.debug("%s replying ARP to %s" % (a.protosrc, a.protodst))
            if a.hwsrc in self.serversMacs:
              msg = of.ofp_flow_mod() 
              msg.match.dl_src = find_client_mac_by_ip(a.protodst)
              msg.match.dl_dst = self.mac
              msg.match.nw_src = a.protodst
              msg.match.nw_dst = self.ip
              msg.idle_timeout = 10
              msg.hard_timeout = 10
              actions = []
              actions.append(of.ofp_action_dl_addr.set_src(self.mac))
              actions.append(of.ofp_action_dl_addr.set_dst(find_server_mac_by_ip(a.protosrc)))
              actions.append(of.ofp_action_nw_addr.set_src(a.protodst))
              actions.append(of.ofp_action_nw_addr.set_dst(a.protosrc))
              actions.append(of.ofp_action_output(port = self.ports.get(find_server_mac_by_ip(a.protosrc))))
              msg.actions = actions
              event.connection.send(msg)


              msg = of.ofp_flow_mod() 
              msg.match.dl_src = find_server_mac_by_ip(a.protosrc)
              msg.match.dl_dst = self.mac
              msg.match.nw_src = a.protosrc
              msg.match.nw_dst = a.protodst
              msg.idle_timeout = 10
              msg.hard_timeout = 10
              actions = []
              actions.append(of.ofp_action_dl_addr.set_src(self.mac))
              actions.append(of.ofp_action_dl_addr.set_dst(find_client_mac_by_ip(a.protodst)))
              actions.append(of.ofp_action_nw_addr.set_src(self.ip))
              actions.append(of.ofp_action_nw_addr.set_dst(a.protodst))
              actions.append(of.ofp_action_output(port = self.ports.get(find_client_mac_by_ip(a.protodst))))
              msg.actions = actions
              a.hwdst = find_client_mac_by_ip(a.protodst)
              a.hwsrc = EthAddr(self.mac)
              a.protosrc = self.ip
              e = ethernet(type=packet.type, src=self.mac, dst=find_client_mac_by_ip(a.protodst))
              e.set_payload(a)
              # msg.data = e.pack()
              event.connection.send(msg)




              a.hwdst = find_client_mac_by_ip(a.protodst)
              a.hwsrc = self.mac
              a.protosrc = self.ip
              e = ethernet(type=packet.type, src=self.mac, dst=find_client_mac_by_ip(a.protodst))
              e.set_payload(a)

              msg = of.ofp_packet_out()
              msg.data = e.pack()
              msg.actions.append(of.ofp_action_output(port = self.ports.get(find_client_mac_by_ip(a.protodst))))
              msg.in_port = inport
              event.connection.send(msg)





            """


            
            """
            # log.info("packet.payload.opcode == arp.REPLY: Probably do something smart here")
            return
        else:
            log.info("Some other ARP opcode, probably do something smart here")
    elif packet.type == ethernet.IP_TYPE:
      log.info("Some IP_TYPE opcode, probably do something smart here")


class load_balancer (object):
  def __init__ (self):
    core.openflow.addListeners(self)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LoadBalancerSwitch(event.connection)


def launch ():
  core.registerNew(load_balancer)
