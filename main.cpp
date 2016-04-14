
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <libnet/libnet-headers.h>



void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


int main()

{

    pcap_t *handle;            /* Session handle */

    char *dev;            /* The device to sniff on */

    char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */

    struct bpf_program fp;        /* The compiled filter */

    char filter_exp[] = "port 23";    /* The filter expression */

    bpf_u_int32 mask;        /* Our netmask */

    bpf_u_int32 net;        /* Our IP */


    /* Define the device */

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {

        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);

        return(2);

    }


    /* Find the properties for the device */

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {

        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);

        net = 0;

        mask = 0;

    }

    /* Open the session in promiscuous mode */

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {

        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);

        return(2);

    }

    /* Compile and apply the filter */

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {

        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));

        return(2);

    }


    pcap_loop(handle, -1, p_packet, NULL);


    /* And close the session */

    pcap_close(handle);

    return(0);

}


void p_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *p)
{

    libnet_ethernet_hdr * p_ether = (libnet_ethernet_hdr *)p;

    printf("\nDestination MAC : %s\n",ether_ntoa((ether_addr *)(p_ether->ether_dhost)));//ether_ntoa => #include <netinet/ether.h>
    printf("Source MAC : %s\n",ether_ntoa((ether_addr *)(p_ether->ether_shost)));

    if(ntohs(p_ether->ether_type)==ETHERTYPE_IP)//0x0800
    {
        libnet_ipv4_hdr * p_ip = (libnet_ipv4_hdr *)(p+sizeof(libnet_ethernet_hdr));

        printf("\nSource IP : %s \n",inet_ntoa(p_ip->ip_src));//struct in_addr ip_src, ip_dst;
        printf("Destination IP : %s \n",inet_ntoa(p_ip->ip_dst));//struct in_addr ip_src, ip_dst;


        if(p_ip->ip_p == IPPROTO_TCP)//#include <netinet/in.h>
        {
            libnet_tcp_hdr * p_tcp = (libnet_tcp_hdr *)(p+sizeof(libnet_ethernet_hdr)+((p_ip->ip_hl)*4));
            printf("\nTCP!!!!!!!!!\n");
            printf("Source Port : %d \n",ntohs(p_tcp->th_sport));
            printf("Destination Port : %d \n",ntohs(p_tcp->th_dport));
        }

        if(p_ip->ip_p ==  IPPROTO_UDP )//#include <netinet/in.h>
        {
            libnet_udp_hdr * p_udp = (libnet_udp_hdr *)(p+sizeof(libnet_ethernet_hdr)+((p_ip->ip_hl)*4));
            printf("\nUDP!!!!!!!!!");
            printf("Source Port : %d \n",ntohs(p_udp->uh_sport));
            printf("Destination Port : %d \n",ntohs(p_udp->uh_dport));
        }

    }




}

