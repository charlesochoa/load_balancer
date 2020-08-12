# load_balancer
Implementar una aplicación SDN completa, específicamente un balanceador de carga en POX


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





::To copy load_balancer.py to mininet virtual machine:

scp -P 3022 "Documents\Unizar\Período 1\Red. Sis Distribuidos\redes-practica2\load_balancer\load_balancer.py" mininet@localhost:/home/mininet/pox/pox/


::To copy topology.py to mininet virtual machine:

scp -P 3022 "Documents\Unizar\Período 1\Red. Sis Distribuidos\redes-practica2\load_balancer\topology.py" mininet@localhost:/home/mininet/mininet/examples

To run it on the virtual machine:


python pox.py log.level --DEBUG load_balancer
