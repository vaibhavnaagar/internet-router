/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO: Add constant definitions here... */
#define arp_protocol_type 0x0800
#define arp_hrd_addr_len ETHER_ADDR_LEN
#define arp_pro_addr_len sizeof(uint32_t)
#define TTL 64
#define IP_VERSION 4
#define IP_HEADER_LENGTH 5
enum arp_type { ARP_REQUEST, ARP_REPLY, ARP_UNKNOWN};
enum icmp_type { ICMP_REQUEST = 8, ICMP_REPLY = 0, ICMP_UNREACHABLE = 3, TIME_EXCEEDED = 11};
enum icmp_code { NET_UNREACHABLE_CODE = 0, HOST_UNREACHABLE_CODE = 1, PORT_UNREACHABLE_CODE = 3 };



/* TODO: Add helper functions here... */

enum arp_type get_arp_type(sr_arp_hdr_t *arp_hdr);
void handle_arp_protocol(struct sr_instance* sr, sr_arp_hdr_t *arp_hdr, char *interface);
int send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t* arp_hdr, struct sr_if* interface);
struct sr_rt* sr_get_rt_entry(struct sr_instance* sr, struct in_addr dest_ip);
int forward_ip_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, uint32_t ip, int forward);
void send_ICMP_packet(struct sr_instance* sr, uint8_t *buf, unsigned int buf_len, enum icmp_type type, enum icmp_code code);
int send_arp_request(struct sr_instance* sr, uint32_t ip);


/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req)
{
  /* TODO: Fill this in */
  time_t now = time(NULL);
  if(difftime(now, req->sent) > 1.0)
  {
    if(req->times_sent >= 5)
    {
      printf("5 arp requests already sent.\n");
      struct sr_packet *old_packets = req->packets;

      while (old_packets != NULL)
      {
        send_ICMP_packet(sr, old_packets->buf, old_packets->len, ICMP_UNREACHABLE, HOST_UNREACHABLE_CODE);
        old_packets = old_packets->next;
      }
      sr_arpreq_destroy(&(sr->cache), req);
    }
    else
    {
      if(send_arp_request(sr, req->ip) != -1)
      { /*Arp request sent successfully*/
        req->sent = now;
        req->times_sent++;
      }
    }
  }
}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* TODO: (opt) Add initialization code here */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  /*sr_print_routing_table(sr);
  sr_print_if_list(sr);*/
  /*printf("*** -> Received packet of length %d\n",len);
  printf("================================================\n");
  print_hdrs(packet, len);*/
  /* TODO: Add forwarding logic here */

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(packet);

  if (ethtype == ethertype_ip)
  { /* IP */
    /*printf("Inside IP\n");*/
    minlength += sizeof(sr_ip_hdr_t);
    if (len < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    uint16_t check_sum = iphdr->ip_sum;
    iphdr->ip_sum = 0;
    if(cksum(iphdr, (iphdr->ip_hl)*4) != check_sum)
    {
      fprintf(stderr, "Check Sum failed !!\n");
      return;
    }

    struct sr_if* iface_list = sr->if_list;
    while (iface_list) {
      if(iface_list->ip == iphdr->ip_dst)
        break;
      iface_list = iface_list->next;
    }
    /* Destined to my router's ip address*/
    if(iface_list)
    {
      uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));

      if (ip_proto == ip_protocol_icmp)
      { /* ICMP */
        minlength += sizeof(sr_icmp_hdr_t);
        if (len < minlength)
        {
          fprintf(stderr, "Failed to find ICMP header, insufficient length\n");
          return;
        }
        /*print_hdr_icmp(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));*/
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        uint16_t icmp_check_sum = icmp_hdr->icmp_sum;
        icmp_hdr->icmp_sum = 0;
        if(cksum(icmp_hdr, (int)(len - sizeof(sr_ethernet_hdr_t) - (iphdr->ip_hl)*4)) != icmp_check_sum)
        {
          fprintf(stderr, "ICMP Check Sum failed !!\n");
          return;
        }

        if(icmp_hdr->icmp_type == ICMP_REQUEST)
          send_ICMP_packet(sr, packet, len, ICMP_REPLY, NET_UNREACHABLE_CODE);

      }
      else
      { /*TCP or UDP*/
        send_ICMP_packet(sr, packet, len, ICMP_UNREACHABLE, PORT_UNREACHABLE_CODE);
      }
      return;
    }

    /*IP forwarding*/
    iphdr->ip_ttl--;
    if(iphdr->ip_ttl == 0)
    {
      send_ICMP_packet(sr, packet, len, TIME_EXCEEDED, NET_UNREACHABLE_CODE);
      return;
    }

    iphdr->ip_sum = 0;
    iphdr->ip_sum = cksum(iphdr, (iphdr->ip_hl)*4);

    uint8_t *new_packet = (uint8_t*)calloc(1, len);
    if(new_packet == NULL)  return;

    memcpy(new_packet, packet, len);

    if(forward_ip_packet(sr, new_packet, len, iphdr->ip_dst, 1) == -1)
      printf("Unable to forward IP packet\n");

    return;
  }
  else if (ethtype == ethertype_arp)
  { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (len < minlength)
      fprintf(stderr, "Failed to find ARP header, insufficient length\n");
    else
    {
      sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

      handle_arp_protocol(sr, arp_hdr, interface);
    }
  }
  else
  {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }

  return;

}/* -- sr_handlepacket -- */


void send_ICMP_packet(struct sr_instance* sr, uint8_t *buf, unsigned int buf_len, enum icmp_type type, enum icmp_code code)
{
  if(sr == NULL || buf == NULL) return;

  /*Again quick sanity check for ip packet */
  int minlength = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
  if (buf_len < minlength || ethertype(buf) != ethertype_ip)  return;

  uint8_t *new_packet = NULL;
  sr_ip_hdr_t *new_ip_hdr = NULL;
  unsigned int new_packet_len = 0;

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));

  struct in_addr dest_ip;
  dest_ip.s_addr = ip_hdr->ip_src;     /*In network byte order*/

  struct sr_rt* rt_entry = sr_get_rt_entry(sr, dest_ip);
  if(rt_entry == NULL)
  {
    printf("No entry found in routing table for ip address of incoming packet\n");
    return;
  }

  struct sr_if* rt_iface = sr_get_interface(sr, rt_entry->interface);
  if(rt_iface == 0)
  {
    printf("Something Wrong !! Unable to get interface of an route entry\n");
    return;
  }

  if(type == ICMP_REPLY)
  { /*Type = 0*/
    new_packet_len = buf_len;
    new_packet = (uint8_t*)calloc(1, new_packet_len);  /*size same as of the icmp request packet*/
    if(new_packet == NULL)  return;

    memcpy(new_packet, buf, buf_len);           /*copies the whole packet*/

    new_ip_hdr = (sr_ip_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));
    new_ip_hdr->ip_ttl = TTL;
    new_ip_hdr->ip_src = ip_hdr->ip_dst;
    new_ip_hdr->ip_dst = ip_hdr->ip_src;

    sr_icmp_hdr_t *new_icmp_hdr = (sr_icmp_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    new_icmp_hdr->icmp_type = type;
    new_icmp_hdr->icmp_code = code;       /*code = 0 for Echo-Reply*/
    new_icmp_hdr->icmp_sum = 0;
    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, (int)(new_packet_len - sizeof(sr_ethernet_hdr_t) - (ip_hdr->ip_hl)*4));
  }
  else
  { /*Type = 3 or 11*/
    /*printf("Inside type 3\n");*/
    new_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    new_packet = (uint8_t*)calloc(1, new_packet_len);

    if(new_packet == NULL)  return;

    new_ip_hdr = (sr_ip_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t));
    new_ip_hdr->ip_hl  = IP_HEADER_LENGTH;
    new_ip_hdr->ip_v   = IP_VERSION;
    new_ip_hdr->ip_tos = 0;
    new_ip_hdr->ip_len = htons(new_packet_len - sizeof(sr_ethernet_hdr_t));
    new_ip_hdr->ip_id  = ip_hdr->ip_id;
    new_ip_hdr->ip_off = htons(IP_DF);
    new_ip_hdr->ip_ttl = TTL;
    new_ip_hdr->ip_p   = ip_protocol_icmp;
    new_ip_hdr->ip_dst = ip_hdr->ip_src;
    new_ip_hdr->ip_src = rt_iface->ip;

    sr_icmp_t3_hdr_t *new_icmp_t3_hdr = (sr_icmp_t3_hdr_t*)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    new_icmp_t3_hdr->icmp_type = type;
    new_icmp_t3_hdr->icmp_code = code;
    memcpy(new_icmp_t3_hdr->data, ip_hdr, ICMP_DATA_SIZE);
    new_icmp_t3_hdr->icmp_sum = 0;
    new_icmp_t3_hdr->icmp_sum = cksum(new_icmp_t3_hdr, (int)(new_packet_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)));


  }

  new_ip_hdr->ip_sum = 0;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, (new_ip_hdr->ip_hl)*4);

  if(forward_ip_packet(sr, new_packet, new_packet_len, ip_hdr->ip_src, 0) == -1)
    printf("Unable to send packet\n");

  return;
}


int forward_ip_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, uint32_t ip, int forward)
{
  if(sr == NULL || packet == NULL)  return -1;

  struct in_addr dest_ip;
  dest_ip.s_addr = ip;     /*In network byte order*/

  struct sr_rt* rt_entry = sr_get_rt_entry(sr, dest_ip);
  if(rt_entry == NULL)
  {
    if(forward == 1)
    {
      printf("non-existent route to the destination IP\n");
      send_ICMP_packet(sr, packet, len, ICMP_UNREACHABLE, NET_UNREACHABLE_CODE);
    }
    return 0;
  }

  struct sr_if* rt_iface = sr_get_interface(sr, rt_entry->interface);
  if(rt_iface == 0)
  {
    printf("Something Wrong !! Unable to get interface of an route entry\n");
    return -1;
  }

  sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)packet;
  memcpy(ehdr->ether_shost, rt_iface->addr, ETHER_ADDR_LEN);

  ehdr->ether_type = htons(ethertype_ip);

  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), rt_entry->gw.s_addr);

  if(arp_entry == NULL)
  {
    /*printf("IP forwarding: GOT null arp entry\n");*/
    struct sr_arpreq *arp_req = sr_arpcache_queuereq(&(sr->cache), rt_entry->gw.s_addr, packet, len, rt_entry->interface);
    handle_arpreq(sr, arp_req);
    /* Packet not freed here*/
    return 0;
  }

  memcpy(ehdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

  int is_sent = 0;
  /*print_hdrs(packet, len);*/
  is_sent = sr_send_packet(sr, packet, len, rt_entry->interface);

  if(packet) free(packet);

  return is_sent;

}


void handle_arp_protocol(struct sr_instance* sr, sr_arp_hdr_t *arp_hdr, char *interface)
{
  if(arp_hdr == NULL || sr == NULL) return;

  enum arp_type ar_type = get_arp_type(arp_hdr);

  if(ar_type == ARP_UNKNOWN)
  {
    printf("ARP: Corrupted ARP packet\n");
    return;
  }

  struct sr_if* arp_iface = sr_get_interface(sr, interface);
  if(arp_iface == 0)
  {
    printf("[ %s ] No such interface exist\n", interface);
    return;
  }

  if(arp_hdr->ar_tip != arp_iface->ip)
  {
    printf("ARP: Target IP is not meant for me\n");
    return;
  }

  if(ar_type == ARP_REQUEST)
  { /* ARP request*/
    /*printf("\n\n\nGOT ARP request\n\n\n");*/
    if(send_arp_reply(sr, arp_hdr, arp_iface) == -1)
      printf("ARP reply not sent\n");
  }
  /* IF arp type is request or reply : in both cases cache is updated and packets
     are sent which are waiting for arp reply  */
  struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), arp_hdr->ar_sip);

  if(entry)
  {
    /*printf("ARP: Entry found in arp cache for ip: ");
    print_addr_ip_int(ntohl(arp_hdr->ar_sip));*/
    free(entry);
  }
  else
  {
    struct sr_arpreq* arp_req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
    /* If an arp request made before is found in arp request queue*/
    if(arp_req)
    {
      struct sr_packet* eth_ip_packet = arp_req->packets;
      while (eth_ip_packet != NULL)
      {
        sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)eth_ip_packet->buf;
        memcpy(ehdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);

        /*print_hdrs(eth_ip_packet->buf, eth_ip_packet->len);*/

        if(sr_send_packet(sr, eth_ip_packet->buf, eth_ip_packet->len, eth_ip_packet->iface) == -1)
          printf("Unable to send packet\n");

        eth_ip_packet = eth_ip_packet->next;
      }
      sr_arpreq_destroy(&(sr->cache), arp_req);
    }
  }

  return;
}


int send_arp_request(struct sr_instance* sr, uint32_t ip)
{
  if(sr == NULL)  return -1;

  uint8_t* buf = (uint8_t*)calloc(1, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  unsigned int buf_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  if(buf == NULL) return -1;

  struct in_addr dest_ip;
  dest_ip.s_addr = ip;     /*In network byte order*/

  struct sr_rt* rt_entry = sr_get_rt_entry(sr, dest_ip);
  if(rt_entry == NULL)  return -1;

  struct sr_if* rt_iface = sr_get_interface(sr, rt_entry->interface);
  if(rt_iface == 0) return -1;

  sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)buf;

  memset(ehdr->ether_dhost, 255, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_shost, rt_iface->addr, ETHER_ADDR_LEN);
  ehdr->ether_type = htons(ethertype_arp);

  sr_arp_hdr_t* hdr = (sr_arp_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));

  hdr->ar_hrd = htons(arp_hrd_ethernet);
  hdr->ar_pro = htons(arp_protocol_type);
  hdr->ar_hln = arp_hrd_addr_len;
  hdr->ar_pln = arp_pro_addr_len;
  hdr->ar_op  = htons(arp_op_request);
  memcpy(hdr->ar_sha, rt_iface->addr, ETHER_ADDR_LEN);
  hdr->ar_sip = rt_iface->ip;        /*Already in network byte order*/
  memset(hdr->ar_tha, 0, ETHER_ADDR_LEN);
  hdr->ar_tip = ip;

  int is_sent = 0;
  /*print_hdrs(buf, buf_len);*/
  is_sent = sr_send_packet(sr, buf, buf_len, rt_entry->interface);

  if(buf) free(buf);

  return is_sent;

}


int send_arp_reply(struct sr_instance* sr, sr_arp_hdr_t *arp_hdr, struct sr_if* interface)
{
  uint8_t* buf = (uint8_t*)calloc(1, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  unsigned int buf_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  if(buf == NULL) return -1;

  struct in_addr dest_ip;
  dest_ip.s_addr = arp_hdr->ar_sip;     /*In network byte order*/

  struct sr_rt* rt_entry = sr_get_rt_entry(sr, dest_ip);
  if(rt_entry == NULL)  return -1;

  struct sr_if* rt_iface = sr_get_interface(sr, rt_entry->interface);
  if(rt_iface == 0) return -1;

  sr_ethernet_hdr_t* ehdr = (sr_ethernet_hdr_t*)buf;

  memcpy(ehdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(ehdr->ether_shost, rt_iface->addr, ETHER_ADDR_LEN);
  ehdr->ether_type = htons(ethertype_arp);

  sr_arp_hdr_t* hdr = (sr_arp_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));

  hdr->ar_hrd = htons(arp_hrd_ethernet);
  hdr->ar_pro = htons(arp_protocol_type);
  hdr->ar_hln = arp_hrd_addr_len;
  hdr->ar_pln = arp_pro_addr_len;
  hdr->ar_op  = htons(arp_op_reply);
  memcpy(hdr->ar_sha, interface->addr, ETHER_ADDR_LEN);
  hdr->ar_sip = interface->ip;        /*Already in network byte order*/
  memcpy(hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  hdr->ar_tip = arp_hdr->ar_sip;

  int is_sent = 0;
  /*print_hdrs(buf, buf_len);*/
  is_sent = sr_send_packet(sr, buf, buf_len, rt_entry->interface);

  if(buf) free(buf);

  return is_sent;

}


struct sr_rt* sr_get_rt_entry(struct sr_instance* sr, struct in_addr dest_ip)
{
  struct sr_rt* rt_walker = sr->routing_table;
  if(rt_walker == 0)
  {
      printf(" *warning* Routing table empty \n");
      return NULL;
  }

  struct sr_rt* rt_copy = NULL;
  uint32_t longest_prefix = 0;

  while(rt_walker)
  {
    if(((rt_walker->dest.s_addr & rt_walker->mask.s_addr) == (dest_ip.s_addr & rt_walker->mask.s_addr))
        && (rt_walker->mask.s_addr > longest_prefix))
    {
      longest_prefix = rt_walker->mask.s_addr;
      /*memcpy(rt_copy, rt_walker, sizeof(struct sr_rt));*/
      rt_copy = rt_walker;
    }
    rt_walker = rt_walker->next;
  }
  return rt_copy;
}


enum arp_type get_arp_type(sr_arp_hdr_t *arp_hdr)
{
  if(arp_hdr == NULL) return ARP_UNKNOWN;

  if(ntohs(arp_hdr->ar_hrd) == arp_hrd_ethernet)
  {
    if(arp_hdr->ar_hln == arp_hrd_addr_len)    /* Check hardware address length : for IPv4 it should be 6*/
    {
      if(ntohs(arp_hdr->ar_pro) == arp_protocol_type)
      {
        if(arp_hdr->ar_pln == arp_pro_addr_len)  /* Check protocol address length : for IPv4 it should be 4*/
        {
          if(ntohs(arp_hdr->ar_op) == arp_op_request)
            return ARP_REQUEST;
          else if(ntohs(arp_hdr->ar_op) == arp_op_reply)
            return ARP_REPLY;
          printf("ARP: Unknown arp opcode\n");
        }
        printf("ARP: Unknown arp protocol address length\n");
      }
      printf("ARP: Unknown arp protocol address type\n");
    }
    printf("ARP: Unknown arp hardware address length\n");
  }
  printf("ARP: Unknown hardware address format\n");
  return ARP_UNKNOWN;
}
