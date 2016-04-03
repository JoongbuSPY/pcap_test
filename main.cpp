
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
    unsigned char s_port[2],d_port[2];
    int port;

    printf("Ethernet!!\n");
    printf("Destination MAC: ");

    for(i=0;i<6;i++)
        printf("%02X ",p[i]);
    printf("\n");

    printf("Source MAC: ");

    for(i=7;i<=12;i++)
        printf("%02X ",p[i]);
    printf("\n");
    printf("\n");

    if(p[12]==0x08 && p[13]==0x00)
        printf("IP Header!!\n");

    printf("IP Source: ");

    for(i=26;i<30;i++)
        printf("%d ",p[i]);
    printf("\n");

    printf("IP Destination: ");

    for(i=30;i<34;i++)
        printf("%d ",p[i]);
    printf("\n");
    printf("\n");

    if(p[23]==0x06)//tcp
    {
        printf("TCP !!!!\n");
        printf("TCP Source Port: ");
        s_port[0]=p[34];
        s_port[1]=p[35];

        port=s_port[0] << 8 | s_port[1];
        printf("%d\n",port);

        printf("TCP Destination Port: ");
        d_port[0]=p[36];
        d_port[1]=p[37];

        port=d_port[0] << 8 | d_port[1];
        printf("%d",port);

        printf("\n");
        printf("\n");

    }

    if(p[23]==0x11)
    {
        printf("UDP!!!!\n");
        printf("UDP Source Port: ");
        s_port[0]=p[34];
        s_port[1]=p[35];

        port=s_port[0] << 8 | s_port[1];
        printf("%d\n",port);

        printf("UDP Destination Port: ");
        d_port[0]=p[36];
        d_port[1]=p[37];

        port=d_port[0] << 8 | d_port[1];
        printf("%d",port);

        printf("\n");
        printf("\n");

    }


}

