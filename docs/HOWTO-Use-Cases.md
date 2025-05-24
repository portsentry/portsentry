# How to use Portsentry

At a high level overview, Portsentry does **three** main things:

* It listens to TCP and/or UDP ports you specify.
* It stealthily (or visibly) logs connection attempts to the ports you have specified.
* It can optionally execute scripts or applications when connection attempts are made.

How could one leverage this into strengthening the Cyber Security posture of an organization? Here are two use-cases where you might want to deploy Portsentry.

## As a complementary Network Intrusion Detection System (NIDS) within your organization

Let's assume your small organisation consist of:

* Office LAN
* WIFI network
* Internal server network

You could put a dedicated instance (server, a virtual machine or a container) running Portsentry on all of these networks and listening to a wide range of ports.

Since this node is not part of the organization, no legitimate traffic should be directed towards it. However, an attacker inside your network will most certainly want to probe your network as part of their reconnaissance and lateral movement. When they do, they will trigger Portsentry and you will be alerted to a potential intruder in your network.

![Portsentry Inside Internal Organization](images/PS-Int-Org.png)

## Enumeration Prevention

Consider a scenario where you have one or several services offered on the public Internet. Portsentry could be deployed to listen for traffic on unused services. Since no legitimate traffic will try to access the unused services, you could block any and all attempts to access the unused services.

Access attempts on unused traffic are more often than not bots, looking for vulnerable services. By blocking them, you interfere with their ability to enumerate your servers, and in some cases even your services (when Portsentry triggers before probes reach legitimate services). This setup also helps protect against targeted enumeration attacks where an adversary is specifically targeting your organization. Blocking an adversary actively enumerating your servers/services could significantly interfere with their attempts. Especially when paired with a "mostly-closed firewall" design, dropping illegitimate traffic.

![Portsentry Blocking Enumeration Attempts](images/PS-Enumeration.png)
