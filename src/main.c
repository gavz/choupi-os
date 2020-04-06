// The MIT License (MIT)
//
// Copyright (c) 2020, National Cybersecurity Agency of France (ANSSI)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Based on STMicroelectronics template, see license there

#include "stm32f4xx_hal.h"
#include <ctype.h>
#include <errno.h>
#include <reent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reent.h>
#include <unistd.h>

static void SystemClock_Config(void);
void Error_Handler(void);

static UART_HandleTypeDef huart;

#ifdef STM32F401xE

// Nucleo-f401re
#include "stm32f401xe.h"
#define USART USART2
#define BUTTON_PORT GPIOC
#define BUTTON_PORT_NUM 2 // ord(C) - ord(A)
#define BUTTON_GPIO 13    // PC13
#define BUTTON_IRQHANDLER EXTI15_10_IRQHandler
#define BUTTON_INTERRUPT_NUM 40 // number of BUTTON_IRQHANDLER in isrvec
#define IRQNUM (1 << BUTTON_GPIO)
#define LED_PORT GPIOA
#define LED_PORT_NUM 0 // ord(A) - ord(A)
#define LED_GPIO 5     // PA5
#define USART_RX GPIO_PIN_2
#define USART_TX GPIO_PIN_3
#define USART_ALT GPIO_AF7_USART2
#define USART_CLK_ENABLE() __USART2_CLK_ENABLE()
#define USART_PORT GPIOA
#define USART_PORT_NUM 0 // ord(A) - ord(A)

#elif defined(STM32F429xx)

// stm32f429i-disc1
#include "stm32f429xx.h"
#define USART USART2
#define BUTTON_PORT GPIOA
#define BUTTON_PORT_NUM 0
#define BUTTON_GPIO 0
#define BUTTON_IRQHANDLER EXTI0_IRQHandler
#define BUTTON_INTERRUPT_NUM 6
#define IRQNUM (1 << 0)
#define LED_PORT GPIOG
#define LED_PORT_NUM 6
#define LED_GPIO 13
#define USART_RX GPIO_PIN_2
#define USART_TX GPIO_PIN_3
#define USART_ALT GPIO_AF7_USART2
#define USART_CLK_ENABLE() __USART2_CLK_ENABLE()
#define USART_PORT GPIOA
#define USART_PORT_NUM 0 // ord(A) - ord(A)

#else
#error "Unknown architecture"
#endif

/********\
|* GPIO *|
\********/

// Enables clock on port `port`
#define PORT_ENABLE(port) (RCC->AHB1ENR |= (1 << (port)))

void gpio_configure(GPIO_TypeDef *port, int gpio, int moder, int otyper,
                    int ospeedr, int pupdr) {
  uint32_t tmp;
  // Configure MODER as output
  tmp = port->MODER;
  tmp &= ~(3 << (gpio * 2));  // 3 is 0b11, reset MODER for the gpio
  tmp |= moder << (gpio * 2); // Output is 0b01
  port->MODER = tmp;
  // Configure OTYPER = 0
  tmp = port->OTYPER;
  tmp &= ~(1 << gpio);
  tmp |= (otyper << gpio);
  port->OTYPER = tmp;
  // Configure PUPDR = 0b00
  tmp = port->PUPDR;
  tmp &= ~(3 << (gpio * 2));
  tmp |= (pupdr << (gpio * 2));
  port->PUPDR = tmp;
  // Configure OSPEEDR = 0b11 (maximal speed)
  tmp = port->OSPEEDR;
  tmp &= ~(3 << (gpio * 2));
  tmp |= (ospeedr << (gpio * 2));
  port->OSPEEDR = tmp;
}

// Configures gpio `gpio` of port `port` as output push-pull max-speed
void gpio_configure_out(GPIO_TypeDef *port, int gpio) {
  gpio_configure(port, gpio, 1, 0, 3, 0);
}

// Configures gpio `gpio` of port `port` as input floating
void gpio_configure_in(GPIO_TypeDef *port, int gpio) {
  gpio_configure(port, gpio, 0, 0, 0, 0);
}

// Toggles a gpio output
void gpio_toggle(GPIO_TypeDef *port, int gpio) { port->ODR ^= (1 << gpio); }

// Sets a gpio output
void gpio_set(GPIO_TypeDef *port, int gpio, int val) {
  uint32_t tmp = port->ODR;
  tmp &= ~((!val) << gpio);
  tmp |= ((!!val) << gpio);
  port->ODR = tmp;
}

// Gets a gpio input
int gpio_get(GPIO_TypeDef *port, int gpio) {
  return (port->IDR & (1 << gpio)) >> gpio;
}

/**************\
|* Interrupts *|
\**************/

// `port` is 0 for PA, 1 for PB, 2 for PC, 3 for PD, 4 for PE, 5 for PF, 6 for
// PG, 7 for PH and 8 for PI
void interrupt_enable(int port, int num, int interrupt, int onrising,
                      int onfalling) {
  uint32_t tmp;
  // Enable SYSCFG (1 << 14 is SYSCFG)
  RCC->APB2ENR |= (1 << 14);
  RCC->APB2RSTR |= (1 << 14);
  RCC->APB2RSTR &= ~(1 << 14);
  // Limit interrupt to specific port
  tmp = SYSCFG->EXTICR[num >> 2];
  tmp &= ~(0xF << ((num & 3) << 2));
  tmp |= (port << ((num & 3) << 2));
  SYSCFG->EXTICR[num >> 2] = tmp;
  // Enable rising edge detection
  tmp = EXTI->RTSR;
  tmp &= ~((!onrising) << num);
  tmp |= ((!!onrising) << num);
  EXTI->RTSR = tmp;
  // Enable falling edge detection
  tmp = EXTI->FTSR;
  tmp &= ~((!onfalling) << num);
  tmp |= ((!!onfalling) << num);
  EXTI->FTSR = tmp;
  // Enable interrupt
  EXTI->IMR |= (1 << num);
  // Unmask interrupt
  NVIC->ISER[interrupt >> 5] |= (1 << (interrupt & 31));
}

void BUTTON_IRQHANDLER() {
  if (EXTI->PR & IRQNUM) {
    gpio_toggle(LED_PORT, LED_GPIO);
    EXTI->PR |= IRQNUM; // Clear interrupt
  }
}

/********\
|* UART *|
\********/

void uart_init() {
  PORT_ENABLE(USART_PORT_NUM);
  huart.Instance = USART;
  huart.Init.BaudRate = 38400;
  huart.Init.WordLength = UART_WORDLENGTH_8B;
  huart.Init.StopBits = UART_STOPBITS_1;
  huart.Init.Parity = UART_PARITY_NONE;
  huart.Init.Mode = UART_MODE_TX_RX;
  huart.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart.Init.OverSampling = UART_OVERSAMPLING_16;
  HAL_UART_Init(&huart);
}
void HAL_UART_MspInit(UART_HandleTypeDef *huart) {
  GPIO_InitTypeDef GPIO_InitStruct;
  if (huart->Instance == USART) {
    USART_CLK_ENABLE();

    GPIO_InitStruct.Pin = USART_RX | USART_TX;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_LOW;
    GPIO_InitStruct.Alternate = USART_ALT;
    HAL_GPIO_Init(USART_PORT, &GPIO_InitStruct);
  }
}

void usart_write(char *ptr, int len) {
  HAL_UART_Transmit(&huart, (uint8_t *)ptr, len, HAL_MAX_DELAY);
}

int _read(int file, char *ptr, int len) {
  if (file != STDIN_FILENO) {
    errno = EBADF;
    return -1;
  }
  char c;
  int i = 0;
  while (i < len) {
    HAL_UART_Receive(&huart, (uint8_t *)&c, 1, HAL_MAX_DELAY);
    if (c == '\r') {
      HAL_UART_Transmit(&huart, (uint8_t *)"\r\n", 2, HAL_MAX_DELAY);
      ptr[i] = '\n';
      return i + 1;
    } else if (c == 0x7F) { // backspace
      if (i != 0) {
        HAL_UART_Transmit(&huart, (uint8_t *)"\b \b", 3, HAL_MAX_DELAY);
        --i;
      }
    } else if (isalnum((int)c) || c == ' ') {
      HAL_UART_Transmit(&huart, (uint8_t *)&c, 1, HAL_MAX_DELAY);
      ptr[i] = c;
      ++i;
    }
  }
  return len;
}

/**************\
 * Rust calls *
\**************/

void heap_init();
void mpu_init();
void fs_dump();

#include "ffi.h"

void ensure(int test) {
  if (!test) {
    puts("Assertion failed!\r");
    while (1)
      Error_Handler();
  } else {
    puts("Assertion passed\r");
  }
}

#ifdef __cplusplus
extern "C" {
#endif
uint8_t mpu_shared_ro_size, mpu_shared_ro_start;
uint8_t mpu_shared_rw_size, mpu_shared_rw_start;
#ifdef __cplusplus
}
#endif

void setup_reent() {}

int main(void) {

  //  FIRST, ZERO-OUT SHARED_RO AND SHARED_RW (as it's not in .data)
  size_t i;
  for (i = 0; i < (size_t)&mpu_shared_ro_size; ++i) {
    (&mpu_shared_ro_start)[i] = 0;
  }
  for (i = 0; i < (size_t)&mpu_shared_rw_size; ++i) {
    (&mpu_shared_rw_start)[i] = 0;
  }

  // Set the first mpu_shared_rw_start as location of _impure_ptr
  struct _reent *init_reent = (((struct _reent *)&mpu_shared_rw_start));

  init_reent->_stdin = _REENT->_stdin;
  init_reent->_stdout = _REENT->_stdout;
  init_reent->_stderr = _REENT->_stderr;

  _impure_ptr = init_reent;

  /* STM32F4xx HAL library initialization:
       - Configure the Flash prefetch, Flash preread and Buffer caches
       - Systick timer is configured by default as source of time base, but user
           can eventually implement his proper time base source (a general
     purpose timer for example or other time source), keeping in mind that Time
     base duration should be kept 1ms since PPP_TIMEOUT_VALUEs are defined and
           handled in milliseconds basis.
       - Low Level Initialization
   */
  HAL_Init();

  /* Configure the System clock to 84 MHz */
  SystemClock_Config();

  /* Configure PA05 IO in output push-pull mode to drive external LED */
  PORT_ENABLE(LED_PORT_NUM);
  gpio_configure_out(LED_PORT, LED_GPIO);

  PORT_ENABLE(BUTTON_PORT_NUM);
  gpio_configure_in(BUTTON_PORT, BUTTON_GPIO);
  interrupt_enable(BUTTON_PORT_NUM, BUTTON_GPIO, BUTTON_INTERRUPT_NUM, 0, 1);

  uart_init();

  heap_init();

  if (fs_init())
    printf("FAILED TO INITIALIZE FS DRIVER\r\n");

  setup_argbuf();

  setup_reent();

  mpu_init();

  uint8_t tag[32], data[8], len, b1;
  uint16_t b2;
  uint32_t b4;
  path_applet_field(0, 0, 0, 0, &tag, &len);
  fs_erase(tag, len);

  ensure(!fs_exists(tag, len));
  ensure(fs_read(tag, len, data, 8) != 0);
  ensure(fs_length(tag, len, &b4) != 0);

  ensure(fs_write(tag, len, (uint8_t const *)"value", 5) == 0);

  memset(data, 0, 8);
  ensure(fs_exists(tag, len));
  ensure(fs_read(tag, len, data, 8) == 0);
  ensure(fs_read_1b_at(tag, len, 4, &b1) == 0);
  ensure(b1 == 'e');
  ensure(fs_read_2b_at(tag, len, 1, &b2) == 0);
  ensure(b2 == 'l' + 0x100 * 'u');
  ensure(fs_read_4b_at(tag, len, 0, &b4) == 0);
  ensure(b4 == 'v' + 0x100 * 'a' + 0x10000 * 'l' + 0x1000000 * 'u');
  ensure(!memcmp(data, "value\0\0\0", 8));
  ensure(fs_length(tag, len, &b4) == 0);
  ensure(b4 == 5);

  ensure(fs_write_4b_at(tag, len, 0, 0x12653487) == 0);
  ensure(fs_read_4b_at(tag, len, 0, &b4) == 0);
  ensure(b4 == 0x12653487);
  ensure(fs_write_2b_at(tag, len, 1, 0xabde) == 0);
  ensure(fs_read_2b_at(tag, len, 1, &b2) == 0);
  ensure(b2 == 0xabde);
  ensure(fs_write_1b_at(tag, len, 3, 0x42) == 0);
  ensure(fs_read_1b_at(tag, len, 3, &b1) == 0);
  ensure(b1 == 0x42);

  ensure(fs_write(tag, len, (uint8_t const *)"value2", 6) == 0);

  memset(data, 0, 8);
  ensure(fs_exists(tag, len));
  ensure(fs_read(tag, len, data, 8) == 0);
  ensure(!memcmp(data, "value2\0\0", 8));
  ensure(fs_length(tag, len, &b4) == 0);
  ensure(b4 == 6);

  ensure(fs_erase(tag, len) == 0);

  ensure(fs_read(tag, len, data, 8) != 0);
  ensure(!fs_exists(tag, len));
  ensure(fs_length(tag, len, &b4) != 0);

  uint8_t data1[8], data2[8];
  memcpy(data1, "foobarbz", 8);
  set_argbuf(data1, 8);
  get_argbuf(data2, 8);
  ensure(!memcmp(data2, "foobarbz", 8));

  memcpy(data1, "barbazfo", 8);
  set_argbuf(data1, 8);
  get_argbuf(data2, 8);
  ensure(!memcmp(data2, "barbazfo", 8));

  // ensure(remote_call(3, 4, 0) == 4 * 3 * 2 * 1);
  // ensure(remote_call(4, 9, 0) == 10);

  puts("All assertions passed\r");

  /// NOTE the following pece of code work only if you uncomment the code ligne
  /// 48 & 55 of filename.rs
  /*
  path_cap(0, &tag, &len);
  if (fs_exists(tag, len)) {
    uint8_t const *data;
    uint32_t datalen;
    ensure(fs_read_inplace(tag, len, &data, &datalen) == 0);
    ensure(datalen == 6);
#define CREATE_CAP 0
#if CREATE_CAP
    puts("CAP 0 already exists\r");
    printf("(contains \"%c%c%c%c%c%c\")\r\n", data[0], data[1], data[2],
           data[3], data[4], data[5]);
#else
    puts("\r\n\n\nERASING CAP0 THEN REBOOTING\r");
    printf("(contained \"%c%c%c%c%c%c\")\r\n\n\n", data[0], data[1], data[2],
           data[3], data[4], data[5]);
    fs_erase_applet(tag, len);
#endif
  } else {
#if !CREATE_CAP
    puts("CAP 0 already deleted\r");
#else
    puts("\r\n\n\nINSTALLING CAP0 THEN REBOOTING\r\n\n");
    fs_write_applet(tag, len, (uint8_t const *)"value3", 6);
#endif
  }*/

  while (1)
    ;

  /* Main loop */
  /* This would have to be entirely rewritten to account for the MPU, except
   * it's not the purpose of this all, so leaving it as a comment
  while (1)
  {
      char buf[64];
      printf("> ");
      scanf("%63s", buf);

      uint32_t tick;
      if (strcmp(buf, "write") == 0) {
          unsigned int sector, idx, val;
          scanf("%x %x %x", &sector, &idx, &val);
          tick = HAL_GetTick();
          flash_write((uint8_t) sector, (uint32_t) idx, (uint8_t) val);
          printf("took %ld ticks, result %ld\r\n", HAL_GetTick() - tick,
  flash_error); flash_error = 0; } else if (strcmp(buf, "erase") == 0) {
          unsigned int sec;
          scanf("%x", &sec);
          fs_drop();
          printf("starting\r\n");
          tick = HAL_GetTick();
          flash_erase((uint8_t) sec);
          printf("took %ld ticks, result %ld\r\n", HAL_GetTick() - tick,
  flash_error); flash_error = 0; if (fs_init()) printf("FAILED TO INITIALIZE FS
  DRIVER\r\n"); } else if (strcmp(buf, "erase0") == 0) { unsigned int sec;
          scanf("%x", &sec);
          fs_drop();
          printf("starting\r\n");
          tick = HAL_GetTick();
          flash_erase0((uint8_t) sec);
          printf("took %ld ticks, result %ld\r\n", HAL_GetTick() - tick,
  flash_error); flash_error = 0; if (fs_init()) printf("FAILED TO INITIALIZE FS
  DRIVER\r\n"); } else if (strcmp(buf, "read") == 0) { unsigned int sector, idx;
          scanf("%x %x", &sector, &idx);
          uint8_t res = flash_read(sector, idx);
          printf("result %ld\r\n", flash_error);
          flash_error = 0;
          printf("Value: hex:%02x / dec:%d / chr:%c\r\n", res, res, res);
      } else if (strcmp(buf, "bench1") == 0) {
          unsigned int sec, x;
          scanf("%x", &sec);
          flash_erase((uint8_t) sec);
          printf("starting bench (10 * erase 1 -> 1)\r\n");
          for (x = 0; x < 10; ++x) {
              flash_erase((uint8_t) sec);
          }
          printf("ending bench\r\n");
      } else if (strcmp(buf, "bench2") == 0) {
          unsigned int sec, x;
          scanf("%x", &sec);
          flash_erase((uint8_t) sec);
          printf("starting bench (10 * erase 1 -> 0 -> 1)\r\n");
          for (x = 0; x < 10; ++x) {
              flash_erase0((uint8_t) sec);
              flash_erase((uint8_t) sec);
          }
          printf("ending bench\r\n");
      } else if (strcmp(buf, "bench3") == 0) {
          unsigned int sec;
          scanf("%x", &sec);
          flash_erase((uint8_t) sec);
          printf("starting bench (1 * erase 1 -> 0 -> 1 -> 0)\r\n");
          flash_erase0((uint8_t) sec);
          flash_erase((uint8_t) sec);
          flash_erase0((uint8_t) sec);
          printf("ending bench\r\n");
      } else if (strcmp(buf, "wtag") == 0) {
          char tag[64], data[64];
          scanf("%63s %63s", tag, data);
          tick = HAL_GetTick();
          uint8_t x = fs_write((uint8_t *) tag, strlen(tag) + 1, (uint8_t *)
  data, strlen(data) + 1); printf("took %ld ticks, result is %d\r\n",
  HAL_GetTick() - tick, x); } else if (strcmp(buf, "rtag") == 0) { char tag[64];
          char * data; uint32_t len;
          scanf("%63s", tag);
          tick = HAL_GetTick();
          uint8_t x = fs_read((uint8_t *) tag, strlen(tag) + 1,
                              (uint8_t **) &data, &len);
          uint32_t ticks = HAL_GetTick() - tick;
          if (x == 0) {
              // Assuming data is null-terminated for this toy example
              printf("Tag %s has value %s\r\n", tag, data);
              fs_free((uint8_t *) data, len);
          } else {
              printf("Unable to find tag %s\r\n", tag);
          }
          printf("took %ld ticks\r\n", ticks);
      } else if (strcmp(buf, "fsdrop") == 0) {
          tick = HAL_GetTick();
          fs_drop();
          printf("took %ld ticks\r\n", HAL_GetTick() - tick);
      } else if (strcmp(buf, "fsinit") == 0) {
          tick = HAL_GetTick();
          if (fs_init()) printf("FAILED TO INITIALIZE FS DRIVER\r\n");
          printf("took %ld ticks\r\n", HAL_GetTick() - tick);
      } else if (strcmp(buf, "wspam") == 0) {
          char tag[64];
          unsigned int num, i;
          char data[2] = { 'a', '\0' };
          scanf("%63s %x", tag, &num);
          tick = HAL_GetTick();
          for (i = 0; i < num; ++i) {
              if (fs_write((uint8_t *) tag, strlen(tag) + 1, (uint8_t *) data,
  2)) { printf("FAILED WRITE\r\n");
              }
              data[0] = (data[0] - 'a' + 1) % 26 + 'a';
          }
          printf("took %ld ticks\r\n", HAL_GetTick() - tick);
      } else if (strcmp(buf, "dumpfs") == 0) {
          fs_dump();
      } else {
          printf("Commands:\r\n");
          printf("  help: prints this help message\r\n");
          printf("  write [SECTOR] [IDX] [VAL]: writes in flash\r\n");
          printf("  erase [SECTOR]: erases sector\r\n");
          printf("  erase0 [SECTOR]: erases sector with 0's\r\n");
          printf("  read [SECTOR] [IDX]: reads value\r\n");
          printf("  bench[123] [SECTOR]: perform benchmarks\r\n");
          printf("  checksum: checksums all the flash by xor-ing each
  byte\r\n"); printf("  wtag [TAG] [DATA]: Writes DATA in a block tagged with
  TAG\r\n"); printf("  rtag [TAG]: Reads block tagged with TAG\r\n"); printf("
  wspam [TAG] [NUM]: spam-writes data to TAG, NUM times\r\n"); printf("  dumpfs:
  retrieves the state of the FS\r\n"); printf("Note: following commands may
  trigger unsafe behaviour\r\n"); printf("  fsinit: Initializes the FS (auto-run
  at startup)\r\n"); printf("  fsdrop: Deinitializes the FS (auto-run at
  startup)\r\n"); printf("Note: all integer values are in hexadecimal
  format\r\n");
      }
  }
  */
}

/**
 * System Clock Configuration
 *   The system Clock is configured as follow :
 *      System Clock source            = PLL (HSI)
 *      SYSCLK(Hz)                     = 84000000
 *      HCLK(Hz)                       = 84000000
 *      AHB Prescaler                  = 1
 *      APB1 Prescaler                 = 2
 *      APB2 Prescaler                 = 1
 *      HSI Frequency(Hz)              = 16000000
 *      PLL_M                          = 16
 *      PLL_N                          = 336
 *      PLL_P                          = 4
 *      PLL_Q                          = 7
 *      VDD(V)                         = 3.3
 *      Main regulator output voltage  = Scale2 mode
 *      Flash Latency(WS)              = 2
 */
static void SystemClock_Config(void) {
  RCC_ClkInitTypeDef RCC_ClkInitStruct;
  RCC_OscInitTypeDef RCC_OscInitStruct;
  HAL_StatusTypeDef status;

  /* Enable Power Control clock */
  __PWR_CLK_ENABLE();

  /* The voltage scaling allows optimizing the power consumption when the device
     is clocked below the maximum system frequency, to update the voltage
     scaling value regarding system frequency refer to product datasheet.  */
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE2);

  /* Enable HSI Oscillator and activate PLL with HSI as source */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = 0x10;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSI;
  RCC_OscInitStruct.PLL.PLLM = 16;
  RCC_OscInitStruct.PLL.PLLN = 336;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV4;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  if ((status = HAL_RCC_OscConfig(&RCC_OscInitStruct)) != HAL_OK) {
    Error_Handler();
  }

  /* Select PLL as system clock source and configure the HCLK, PCLK1 and PCLK2
     clocks dividers */
  RCC_ClkInitStruct.ClockType = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK |
                                 RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2);
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;
  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK) {
    Error_Handler();
  }

  /* Enable HSE Oscillator
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;

  if((status = HAL_RCC_OscConfig(&RCC_OscInitStruct)) != HAL_OK)
  {
      Error_Handler();
  }
  */
}

void Error_Handler(void) {
  volatile uint32_t x;
  while (1) {
    gpio_toggle(LED_PORT, LED_GPIO);
    for (x = 0; x < 0xFFFFF; ++x)
      ;
  }
}

#pragma GCC push_options
#pragma GCC optimize("O0")
void do_malloc() {
  void *test = malloc(1);
  free(test);
}
#pragma GCC pop_options
