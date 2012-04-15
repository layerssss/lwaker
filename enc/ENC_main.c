/*********************************************
 * modified: 2007-08-08
 * Author  : awake
 * Copyright: GPL V2
 * http://www.icdev.com.cn/?2213/
 * Host chip: ADUC7026
**********************************************/




//#include "SAM7SDK_BSP.h"
#include <atmel\sam7s\AT91SAM7S64.h>
#include "enc28j60.h"

const unsigned char enc28j60_MAC[6] = {0x54,0x55,0x58,0x10,0x00,0x24};

extern int simple_server(void);

int ENC_main(void)
{
    int rev = 0;

//    SAMDK_Init();
    
    //__enable_irq();

	
	
    simple_server();

    enc28j60Init((unsigned char *)enc28j60_MAC);

    rev = enc28j60getrev();

    return rev;
}
