#include <atmel\sam7s\AT91SAM7S64.h>
#define u32 unsigned long
#define u16 unsigned int
#define u8 unsigned char

#define SPISend(data) (AT91C_BASE_SPI->SPI_TDR=data&0x0000FFFF)
#define SPIRead() (AT91C_BASE_SPI->SPI_RDR&AT91C_SPI_RD)
#define SPICanSend() (AT91C_BASE_SPI->SPI_SR&AT91C_SPI_TDRE)
#define SPICanRead() (AT91C_BASE_SPI->SPI_SR&AT91C_SPI_RDRF)
