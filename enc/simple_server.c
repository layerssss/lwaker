
/*********************************************
 * Author: Zhixiang Yin
 * Copyright: GPL V2
 * See http://www.gnu.org/licenses/gpl.html
 *
 * Title: Wake on Lan MCU (micro controlling unit) 
 * https://github.com/layerssss/lwaker
 * Chip type           : AT91SAM7S64 with ENC28J60
 *********************************************/

/*********************************************
 * modified: 2010-10-01
 * Author  : awake
 * Copyright: GPL V2
 * http://www.icdev.com.cn/?2213/
 * Host chip: ADUC7026
**********************************************/




#include "ip_arp_udp_tcp.h"
#include "enc28j60.h"
#include "net.h"
#include "s64.h"





#include <string.h>

#define PSTR(s) s

extern void delay_ms(unsigned char ms);

// My MAC address
uint8_t mymac[6] = {0x54,0x55,0x58,0x10,0x00,0x24};
uint8_t dmac[6]={0x00,0x07,0xe9,0x11,0x65,0x19};
uint8_t fmac[6]={0x00,0x07,0xe9,0x11,0x65,0x19};
uint8_t fip[4] = {192,168,1,2};
uint8_t myip[4] = {192,168,1,25};
uint16_t mywwwport =81; // listen port for tcp/www (max range 1-254)

#define BUFFER_SIZE 1500//400
uint8_t buf[BUFFER_SIZE+1];
uint8_t wolbuf[500];

// the password string (only the first 5 char checked), (only a-z,0-9,_ characters):
char password[]="tlzyda"; // must not be longer than 9 char
 
uint8_t verify_password(char *str)
{
        // the first characters of the received string are
        // a simple password/cookie:
        if (strncmp(password,str,sizeof(password)-1)==0){
                return(1);
        }
        return(0);
}

// takes a string of the form password/commandNumber and analyse it
// return values: -1 invalid password, otherwise command number
//                -2 no command given but password valid
int8_t analyse_get_url(char *str)
{
        uint8_t i=0;
        if (verify_password(str)==0){
                return(-1);
        }
        // find first "/"
        // passw not longer than 9 char:
        while(*str && i<10 && *str >',' && *str<'{'){
                if (*str=='/'){
                        str++;
                        break;
                }
                i++;
                str++;
        }
        if (*str < 0x3a && *str > 0x2f){
                // is a ASCII number, return it
                return(*str-0x30);
        }
        return(-2);
}

// prepare the webpage by writing the data to the tcp send buffer
uint16_t print_webpage(uint8_t *buf,uint8_t on_off,uint8_t i)
{
        uint16_t plen;
        plen=fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nPragma: no-cache\r\n\r\n"));
		plen=fill_tcp_data_p(buf,plen,PSTR("<style type=\"text/css\">"));
		plen=fill_tcp_data_p(buf,plen,PSTR("body{background-color:#eee;}"));
		plen=fill_tcp_data_p(buf,plen,PSTR("a{padding:3px;background-color:#ccc;color:#000;text-decoration:none;border:1px solid #222;}"));
		plen=fill_tcp_data_p(buf,plen,PSTR("a:hover{background-color:#aaa;text-decoration:underlined;}"));
		plen=fill_tcp_data_p(buf,plen,PSTR("a:active,a.active,a.active:hover{background-color:#eee;text-decoration:underlined;}"));
		plen=fill_tcp_data_p(buf,plen,PSTR("</style>"));
        plen=fill_tcp_data_p(buf,plen,PSTR("<center><p>电源状态："));
		if (on_off){
                plen=fill_tcp_data_p(buf,plen,PSTR("<font color=\"#00FF00\">已通电</font>"));
        }else{
                plen=fill_tcp_data_p(buf,plen,PSTR("已断电"));
        }
        plen=fill_tcp_data_p(buf,plen,PSTR(" <small><a href=\"/"));
        plen=fill_tcp_data(buf,plen,password);
        plen=fill_tcp_data_p(buf,plen,PSTR("\">[刷新]</a></small></p>\n<p><a href=\"/"));
        // the url looks like this http://baseurl/password/command
        plen=fill_tcp_data(buf,plen,password);
        plen=fill_tcp_data_p(buf,plen,PSTR("/1\">Wake On Lan!</a></p>\n<p><a href=\"/"));
		plen=fill_tcp_data(buf,plen,password);
		if (i){					   
                plen=fill_tcp_data_p(buf,plen,PSTR("/3\" class=\"active\">抬起按钮</a><p>"));
        }else{
                plen=fill_tcp_data_p(buf,plen,PSTR("/2\">按下按钮</a><p>"));
        }
        plen=fill_tcp_data_p(buf,plen,PSTR("</center><hr><br>LayersSss制造\n"));
        return(plen);
}











int simple_server(void)
{      
        uint16_t plen;
        uint16_t dat_p;
        uint8_t butstat=0;
		uint8_t ledstat=0;
        int8_t cmd;
		

        
        delay_ms(200);
        
        /*initialize enc28j60*/
        enc28j60Init(mymac);
		enc28j60clkout(2); // change clkout from 6.25MHz to 12.5MHz
        delay_ms(20);
        
        enc28j60PhyWrite(PHLCON,0xd76);	//0x476	  
        delay_ms(20);
        

        //init the ethernet/ip layer:
        init_ip_arp_udp_tcp(mymac,myip,mywwwport);
		
		//printf("Chip var:0x%x \n",enc28j60getrev());


		

        while(1)
        {

                // get the next new packet:
                 plen = enc28j60PacketReceive(BUFFER_SIZE, buf);

                /*plen will ne unequal to zero if there is a valid 
                 * packet (without crc error) */
                if(plen==0)
                {
                        continue;
                }
                // arp is broadcast if unknown but a host may also
                // verify the mac address by sending it to 
                // a unicast address.
                if(eth_type_is_arp_and_my_ip(buf,plen))
                {
                       
						make_arp_answer_from_request(buf);
						//printf("make_arp_answer_from_request\n");
                        continue;
                }

                // check if ip packets are for us:
                if(eth_type_is_ip_and_my_ip(buf,plen)==0)
                {
                        continue;
                }

                
                if(buf[IP_PROTO_P]==IP_PROTO_ICMP_V && buf[ICMP_TYPE_P]==ICMP_TYPE_ECHOREQUEST_V)
                {
                        // a ping packet, let's send pong	
						make_echo_reply_from_request(buf, plen);
						//printf("make_echo_reply_from_request\n");
						continue;
                }
               // tcp port www start, compare only the lower byte
               if (buf[IP_PROTO_P]==IP_PROTO_TCP_V&&buf[TCP_DST_PORT_H_P]==0&&buf[TCP_DST_PORT_L_P]==mywwwport){
                        if (buf[TCP_FLAGS_P] & TCP_FLAGS_SYN_V){
                                make_tcp_synack_from_syn(buf);
                                // make_tcp_synack_from_syn does already send the syn,ack
                                continue;
                        }
                        if (buf[TCP_FLAGS_P] & TCP_FLAGS_ACK_V){
                                init_len_info(buf); // init some data structures
                                // we can possibly have no data, just ack:
                                dat_p=get_tcp_data_pointer();
                                if (dat_p==0){
                                        if (buf[TCP_FLAGS_P] & TCP_FLAGS_FIN_V){
                                                // finack, answer with ack
                                                make_tcp_ack_from_any(buf);
                                        }
                                        // just an ack with no data, wait for next packet
                                        continue;
                                }
							
							
                                if (strncmp("GET ",(char *)&(buf[dat_p]),4)!=0){
                                        // head, post and other methods:
                                        //
                                        // for possible status codes see:
                                        // http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
                                        plen=fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>200 OK</h1>"));
                                        goto SENDTCP;
                                }
                                if (strncmp("/ ",(char *)&(buf[dat_p+4]),2)==0){
                                        plen=fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"));
                                        plen=fill_tcp_data_p(buf,plen,PSTR("<p>Usage: \\"));
                                        plen=fill_tcp_data_p(buf,plen,PSTR("password</p>"));
                                        goto SENDTCP;
                                }
                                cmd=analyse_get_url((char *)&(buf[dat_p+5]));
                                // for possible status codes see:
                                // http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
                                if (cmd==-1){
                                        plen=fill_tcp_data_p(buf,0,PSTR("HTTP/1.0 401 Unauthorized\r\nContent-Type: text/html\r\n\r\n<h1>401 Unauthorized</h1>"));
                                        goto SENDTCP;
                                }
                                if (cmd==1){
                                        //WOL
										make_wol_on_ip(wolbuf,dmac);
										//WOL end
                                }
                                if (cmd==2){
								        //Press the button.						   
                                        AT91C_BASE_PIOA->PIO_CODR=0x2;
										butstat=1;
                                }
								if (cmd==3){
										//Release the button.					   
                                        AT91C_BASE_PIOA->PIO_SODR=0x2;
										butstat=0;
                                }
                                // if (cmd==-2) or any other value
                                // just display the status:
								ledstat=0x1&((*AT91C_PIOA_PDSR)>>0);
                                plen=print_webpage(buf,ledstat,butstat);
                               
SENDTCP:
                                make_tcp_ack_from_any(buf); // send ack for http get
                                make_tcp_ack_with_data(buf,plen); // send data
                                continue;
                        }

                }
		}
}
