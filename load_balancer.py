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

    self.switchMac = EthAddr("00:00:00:00:00:" + str(HOST_NUMBER+1))
    self.switchIp = IPAddr("10.0.0." + str(HOST_NUMBER+1))
    # self.clientsMacs = [EthAddr("00:00:00:00:00:" + str(x)) for x in  range(1,HOST_NUMBER/2 +1) ]
    # self.serversMacs = [EthAddr("00:00:00:00:00:" + str(x)) for x in  range(HOST_NUMBER/2 +1,HOST_NUMBER +1) ]
    self.hosts = {}
    self.clientsIps = [IPAddr("10.0.0." + str(x)) for x in  range(1,HOST_NUMBER/2 +1) ]
    self.serversIps = [IPAddr("10.0.0." + str(x)) for x in  range(HOST_NUMBER/2 +1,HOST_NUMBER +1) ]
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


    log.info("PACKET_IN")
    inport = event.port
    packet = event.parsed

    def select_server():
      return 0
      # return random.randint(0,5)

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
            self.hosts[a.protosrc] = (a.hwsrc, inport)
            log.info("self.hosts")
            log.info(self.hosts)
            if a.protosrc in self.clientsIps:
              selectedServer = self.serversIps[select_server()]
              a.hwsrc = self.switchMac
              a.protodst = selectedServer
              e = ethernet(type=ethernet.ARP_TYPE, src=self.switchMac, dst=ETHER_BROADCAST)
              e.set_payload(a)
              log.debug("%s requesting ARP to %s" % (a.protosrc, a.protodst))
              msg = of.ofp_packet_out()
              msg.data = e.pack()
              msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
              event.connection.send(msg)
              return
            elif a.protosrc in self.serversIps:
              log.warning("Receiving an ARP request from a server!!")
              log.debug("%s (%s) => %s (%s)" % (a.protosrc, a.hwsrc, a.protodst, a.hwdst))
              r = arp()
              r.opcode = arp.REPLY
              r.hwsrc = self.switchMac
              r.hwdst = a.hwsrc
              r.protosrc = a.protodst
              r.protodst = a.protosrc
              e = ethernet(type=ethernet.ARP_TYPE, src=self.switchMac, dst=r.hwdst)
              e.set_payload(r)
              log.debug("%s (%s) replying ARP to %s (%s)" % (r.protosrc, r.hwsrc, r.protodst, r.hwdst))
              msg = of.ofp_packet_out()
              msg.data = e.pack()
              msg.actions.append(of.ofp_action_output(port = inport))
              event.connection.send(msg)
              return

        elif packet.payload.opcode == arp.REPLY:
            log.info("arp.REPLY == true")
            a = packet.next
            self.hosts[a.protosrc] = (a.hwsrc, inport)
            log.info("self.hosts")
            log.info(self.hosts)
            log.debug("%s (%s) replying ARP to %s (%s)" % (a.protosrc, a.hwsrc, a.protodst, a.hwdst))
            if a.protosrc in self.serversIps:
              clientIp = a.protodst
              serverIp = a.protosrc
              clientMac, clientPort = self.hosts[clientIp]
              serverMac, serverPort = self.hosts[serverIp]

              msg = of.ofp_flow_mod()
              msg.match.dl_type = 0x800 
              msg.match.dl_src = clientMac
              msg.match.dl_dst = self.switchMac
              msg.match.nw_src = clientIp
              msg.match.nw_dst = self.switchIp
              msg.idle_timeout = 10
              msg.hard_timeout = 10
              actions = []
              actions.append(of.ofp_action_dl_addr.set_src(self.switchMac))
              actions.append(of.ofp_action_dl_addr.set_dst(serverMac))
              actions.append(of.ofp_action_nw_addr.set_src(clientIp))
              actions.append(of.ofp_action_nw_addr.set_dst(serverIp))
              actions.append(of.ofp_action_output(port = serverPort))
              msg.actions = actions
              event.connection.send(msg)
              log.debug("First flowMod: from %s (%s) ==> %s (%s)" % (clientIp,clientMac,serverIp,serverMac))

              msg = of.ofp_flow_mod() 
              msg.match.dl_type = 0x800 
              msg.match.dl_src = serverMac
              msg.match.dl_dst = self.switchMac
              msg.match.nw_src = serverIp
              msg.match.nw_dst = clientIp
              msg.idle_timeout = 10
              msg.hard_timeout = 10
              actions = []
              actions.append(of.ofp_action_dl_addr.set_src(self.switchMac))
              actions.append(of.ofp_action_dl_addr.set_dst(clientMac))
              actions.append(of.ofp_action_nw_addr.set_src(self.switchIp))
              actions.append(of.ofp_action_nw_addr.set_dst(clientIp))
              actions.append(of.ofp_action_output(port = clientPort))
              msg.actions = actions
              event.connection.send(msg)
              log.debug("Second flowMod: from %s (%s) <== %s (%s)" % (clientIp,clientMac,serverIp,serverMac))


              r = arp()
              r.opcode = arp.REPLY
              r.hwsrc = self.switchMac
              r.hwdst = clientMac
              r.protosrc = self.switchIp
              r.protodst = clientIp
              e = ethernet(type=ethernet.ARP_TYPE, src=self.switchMac, dst=clientMac)
              e.set_payload(r)
              log.debug("%s Replying ARP to %s" % (r.protosrc, r.protodst))
              msg = of.ofp_packet_out()
              msg.data = e.pack()
              msg.actions.append(of.ofp_action_output(port = clientPort))
              msg.in_port = inport
              event.connection.send(msg)
              log.debug("Third packetOut: from %s (%s) -> %s (%s)" % (r.protosrc,r.hwsrc,r.protodst,r.hwdst))

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
