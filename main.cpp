
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>


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
    int i=0;
    const u_char * packet_eh=p;
    const u_char * packet_type=p+12;
    const u_char * packet_ip=p+14;
    const u_char * packet_protocol=0x00;
    const u_char * packet_tcp_udp=p+34;

    printf("Ethernet!!\n");
    printf("Destination MAC: ");

    for(i=0;i<6;i++)
    {
        printf("%02X",*(packet_eh+i));
        if(i<5)
            printf(":");
    }

    printf("\n");

    printf("Source MAC: ");

    for(i=6;i<12;i++)
    {
          printf("%02X",(*packet_eh+i));
        if(i<11)
            printf(":");
    }

    printf("\n");
    printf("\n");

    if(*(packet_type)==0x08 && *(packet_type+1)==0x00)//IP
    {
        packet_protocol=packet_ip+9;

        printf("IP Header!!\n");
        printf("IP Source: ");

         for(i=12;i<16;i++)
         {
              printf("%d",*(packet_ip+i));
              if(i<15)
                  printf(".");
           }

        printf("\n");

         printf("IP Destination: ");

        for(i=16;i<20;i++)
        {
            printf("%d",*(packet_ip+i));
            if(i<19)
                printf(".");
        }

        printf("\n");
        printf("\n");

        if((*packet_protocol)==0x06)//tcp
        {
            printf("TCP !!!!\n");
            printf("TCP Source Port: ");
            printf("%d\n",(*packet_tcp_udp) << 8 | *(packet_tcp_udp+1));

            printf("TCP Destination Port: ");

            printf("%d\n",*(packet_tcp_udp+2) << 8 | *(packet_tcp_udp+3));

            printf("\n");
            printf("\n");

        }

        else if((*packet_protocol)==0x11)//udp
        {
            printf("UDP!!!!\n");
            printf("UDP Source Port: ");
            printf("%d\n",(*packet_tcp_udp) << 8 | *(packet_tcp_udp+1));

            printf("UDP Destination Port: ");
            printf("%d\n",(*packet_tcp_udp+2) << 8 | *(packet_tcp_udp+3));

            printf("\n");
            printf("\n");

        }

    }

   }


