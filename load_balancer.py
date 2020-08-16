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
HOST_NUMBER = 12

class LoadBalancerSwitch (object):

  def __init__ (self, connection):
    self.connection = connection

    self.switchMac = EthAddr("00:00:00:00:00:" + str(HOST_NUMBER+1))
    self.switchIp = IPAddr("10.0.0." + str(HOST_NUMBER+1))
    self.serversMacs = [EthAddr("00:00:00:00:00:" + str(x)) for x in  range(HOST_NUMBER/2 +1,HOST_NUMBER +1) ]
    self.hosts = {}
    self.pendingPackets = {}
    self.serversIps = [IPAddr("10.0.0." + str(x)) for x in  range(HOST_NUMBER/2 +1,HOST_NUMBER +1) ]
    self.serversPorts = [7,8,9,10,11,12]
    self.turn = 5
    # We want to hear PacketIn messages, so we listen
    # to the connection
    connection.addListeners(self)

    log.debug("Initializing Load Balancer")
    log.debug("Clients")
    log.debug("Servers")
    log.debug(self.serversIps)
      
  

  def _handle_PacketIn (self, event):


    log.debug("PACKET_IN")
    inport = event.port
    packet = event.parsed

    def select_server():
      #self.turn = (self.turn + 1) % 6
      #return self.turn
      return random.randint(0,5)

    if packet.type == packet.ARP_TYPE:
        a = packet.next
        log.debug("packet is ARP_TYPE")
        if packet.payload.opcode == arp.REQUEST:
          log.debug("payload is arp.REQUEST from %s" % (a.protosrc))
          macdst = a.hwsrc
          macsrc = self.switchMac
          ipsrc = a.protodst
          ipdst = a.protosrc

          a.opcode = arp.REPLY
          a.hwsrc = macsrc
          a.hwdst = macdst
          a.protosrc = ipsrc
          a.protodst = ipdst
          e = ethernet(type=ethernet.ARP_TYPE, src=self.switchMac, dst=macdst)
          e.set_payload(a)
          log.debug("%s (%s) replying ARP to %s (%s)" % (a.protosrc, a.hwsrc, a.protodst, a.hwdst))
          msg = of.ofp_packet_out()
          msg.data = e.pack()
          msg.actions.append(of.ofp_action_output(port = inport))
          event.connection.send(msg)
          return

        elif packet.payload.opcode == arp.REPLY:
            a = packet.next
            log.debug("payload is arp.REPLY %s" % (a.protosrc))
            log.debug("%s (%s) ARP reply to %s (%s). Droped." % (a.protosrc, a.hwsrc, a.protodst, a.hwdst))
           
            return
        else:
            log.warning("Some other ARP opcode, probably do something smart here")
    elif packet.type == ethernet.IP_TYPE:
      if packet.find('icmp') != None:
        a = packet.next
        if a.srcip not in self.serversIps:
          log.debug("IP TYPE from %s Selecting a new server to respond" % (a.srcip))
          selectedServer = select_server()
          serverIp = self.serversIps[selectedServer]
          serverMac = self.serversMacs[selectedServer]
          serverPort = self.serversPorts[selectedServer]
          log.debug("Selected Server: %s" % serverIp)
          clientIp = a.srcip
          clientMac = packet.src
          clientPort = inport

          msg = of.ofp_flow_mod()
          msg.match.dl_type = pkt.ethernet.IP_TYPE 
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
          log.debug("FlowMod: from %s (%s) ==> %s (%s)" % (clientIp,clientMac,serverIp,serverMac))

          msg = of.ofp_flow_mod() 
          msg.match.dl_type = pkt.ethernet.IP_TYPE
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
          log.debug("FlowMod: from %s (%s) <== %s (%s)" % (clientIp,clientMac,serverIp,serverMac))

          a.dstip = serverIp
          e = ethernet(type=ethernet.IP_TYPE, src=self.switchMac, dst=serverMac)
          e.set_payload(a)
          log.debug("PacketOut: %s Requesting ICMP to %s" % (a.srcip, a.dstip))
          msg = of.ofp_packet_out()
          msg.data = e.pack()
          msg.actions.append(of.ofp_action_output(port = serverPort))
          msg.in_port = inport
          event.connection.send(msg)

        

def _timer_func ():
  for connection in core.openflow._connections.values():
    connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))

def _handle_portstats_received (event):
  log.info(" ")
  log.info(" ")
  log.info(" ")
  log.info("Results:")
  log.info(" ")
  for s in event.stats:
    log.info("Port %s: rx %s, tx %s", s.port_no, s.rx_packets, s.tx_packets)

class load_balancer (object):
  def __init__ (self):
    core.openflow.addListeners(self)

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LoadBalancerSwitch(event.connection)


def launch ():
  from pox.lib.recoco import Timer

  core.openflow.addListenerByName("PortStatsReceived", _handle_portstats_received) 
  core.registerNew(load_balancer)
  Timer(5, _timer_func, recurring=True)

