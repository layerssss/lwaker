#include <atmel\sam7s\AT91SAM7S64.h>
#define u32 unsigned long
#define u16 unsigned int
#define u8 unsigned char

#define SPISend(data) AT91C_BASE_SPI.SPI_TD=data;
#define SPIRcv(buf) data=AT91C_BASE_SPI.SPI_TD.SPI_RDR;
void SPI_init(void)
{
//PMC_PCER=(AT91C_PA12_MISO|AT91C_PA13_MOSI|AT91C_PA14_SPCK|AT91C_PA11_NPCS0);
* AT91C_PMC_PCER =0x20;
//PIO���蹦��ʱ��ʼ��

*AT91C_PIOA_PDR =(AT91C_PA12_MISO|AT91C_PA13_MOSI|AT91C_PA14_SPCK|AT91C_PA11_NPCS0);
//PIOʹ�����ŵ����蹦��

*AT91C_PIOA_ASR=(AT91C_PA12_MISO|AT91C_PA13_MOSI|AT91C_PA14_SPCK|AT91C_PA11_NPCS0);
//����A�����SPI����A����



*AT91C_SPI_CR=AT91C_SPI_SPIEN ;
//����SPI��
*AT91C_SPI_MR=(AT91C_SPI_MSTR|AT91C_SPI_PS_FIXED|AT91C_SPI_MODFDIS|AT91C_SPI_DLYBCS);
//����ģʽ,����Ƶ,�̶�Ƭѡ0,��ֹ������
*AT91C_SPI_CSR=(AT91C_SPI_NCPHA|AT91C_SPI_CSAAT|AT91C_SPI_BITS_8|(12<<8)|AT91C_SPI_DLYBS|AT91C_SPI_DLYBCT);
//8λ���ݣ�������ɺ�Ƭѡ���֣�48M/12��Ƶ������ǰ��ʱ255������������ʱ255 AT91C_SPI_SCBR



}
 void delayMS(u32 c)
 {
 	u32 i,b;
	b=c<<12;
 	for(i=0;i<b;i++)
	{
	}
 }
 void Init_input(u32 set)
{
	* AT91C_PMC_PCER =1<<AT91C_ID_PIOA;
	AT91C_BASE_PIOA->PIO_PER=set;
	AT91C_BASE_PIOA->PIO_ODR=set;
	AT91C_BASE_PIOA->PIO_IFER=set;
	AT91C_BASE_PIOA->PIO_CODR=set;
	AT91C_BASE_PIOA->PIO_MDDR=set;
	AT91C_BASE_PIOA->PIO_PPUER=set;
	AT91C_BASE_PIOA->PIO_OWDR=set;
	* AT91C_PIOA_IFER=set;
}
void Init_output(u32 set)
{
	AT91C_BASE_PIOA->PIO_PER=set;
	AT91C_BASE_PIOA->PIO_OER=set;
	AT91C_BASE_PIOA->PIO_SODR=set;
}
int main()
{
	Init_input(0x1<<0);
	Init_output(0x1<<1);
	AT91C_BASE_PIOA->PIO_PER=1<<15;
	AT91C_BASE_PIOA->PIO_OER=1<<15;
	AT91C_BASE_PIOA->PIO_SODR=1<<1;
	ENC_main();

}
