/*
Midbar Firebase Edition
Distributed under the MIT License
© Copyright Maxim Bortnikov 2023
For more information please visit
https://sourceforge.net/projects/midbar-firebase-edition/
https://github.com/Northstrix/Midbar-Firebase-Edition
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/peterferrie/serpent
https://github.com/ddokkaebi/Blowfish
https://github.com/Northstrix/DES_and_3DES_Library_for_MCUs
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/intrbiz/arduino-crypto
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/mobizt/Firebase-ESP32
*/
#include <Arduino.h>
#include <WiFi.h>
#include <FirebaseESP32.h>
#include <SPI.h>
#include <Adafruit_GFX.h>
#include <Adafruit_ST7735.h>
#include <PS2KeyAdvanced.h>
#include <PS2KeyMap.h>
#include "addons/TokenHelper.h"
#include "addons/RTDBHelper.h"
#include "DES.h"
#include "aes.h"
#include "blowfish.h"
#include "serpent.h"
#include "Crypto.h"
#include "sha512.h"
#include "custom_hebrew_font.h"
#include "lock_screens.h"

#define WIFI_SSID "accessPpointName"
#define WIFI_PASSWORD "accessPointPassword"
#define API_KEY "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
#define DATABASE_URL "https://database-name-default-rtdb.firebaseio.com/"
#define TFT_CS1         5
#define TFT_RST1        19
#define TFT_DC1         22
#define DATAPIN 26
#define IRQPIN 25
Adafruit_ST7735 tft = Adafruit_ST7735(TFT_CS1, TFT_DC1, TFT_RST1);

#define MAX_NUM_OF_RECS 999
#define DELAY_FOR_SLOTS 24

DES des;
Blowfish blowfish;
FirebaseData fbdo;
FirebaseAuth auth;
FirebaseConfig config;
PS2KeyAdvanced keyboard;
PS2KeyMap keymap;

int m;
int clb_m;
String dec_st;
String dec_tag;
byte tmp_st[8];
int pass_to_serp[16];
int decract;
byte array_for_CBC_mode[10];
String input_from_the_ps2_keyboard;
byte sdown = 36;
uint16_t code;
int curr_key;
int curr_pos;
int prsd_key;
bool finish_input;
bool act;
bool decrypt_tag;
byte data_from_keyboard;
bool rec_d;
uint16_t colors[4] = { // Purple, Yellow, Green, Blue
  0xb81c, 0xfde0, 0x87a0, 0x041c
};
const uint16_t current_inact_clr = colors[3];
const uint16_t five_six_five_red_color = 0xf940;
const uint16_t stripe_on_the_right_color = 0xfa40;
#define letter_spacing_pxls 6
#define regular_shift_down 16
#define shift_down_for_mem 12
String succs_ver_inscr = "Integrity Verif Success!";
String faild_ver_inscr = "Integrity Verif Failed!";
String fuid = ""; 
bool isAuthenticated = false;

// Keys (Below)

byte read_cards[16] = {
0xbe,0x70,0x0e,0x3e,0x55,0x71,0xfd,0xdb,
0xdb,0xdf,0x5e,0xcc,0xb2,0x61,0xba,0x63
};
String kderalgs = "8z7EHhn0Gw819793KhBei1V9c";
int numofkincr = 948;
byte hmackey[] = {"WmJ0I85quL87li6W7OEUTEeRk9R0vvpwi4NVqN3bkb09H9NQK5p2371v6Nkx7M5QcjXrppcSahLo9Ivbq51911AwkI89Ik4k47VVCu4WMRRl14Wt9582Q9k58wGhm6I6"};
byte des_key[] = {
0x3a,0xab,0x66,0x62,0xde,0xff,0x21,0xd3,
0x64,0xed,0xc6,0x67,0xa8,0xe0,0xbb,0xcf,
0x0d,0xac,0xaa,0xc3,0x25,0xdc,0xb2,0xb5
};
uint8_t AES_key[32] = {
0xf7,0xe5,0xde,0xec,
0xee,0xd0,0x24,0x76,
0x63,0x85,0xbb,0x84,
0x0a,0x20,0x26,0xbd,
0xfd,0x07,0xcd,0x4c,
0xdc,0x86,0x1a,0xd1,
0xcb,0x3e,0x69,0x15,
0x1c,0x6c,0x3a,0xa2
};
unsigned char Blwfsh_key[] = {
0xbb,0x8a,0xa3,0xe6,
0xba,0x28,0x0b,0xf4,
0xbd,0xff,0x7a,0xf5,
0xa2,0xdf,0x22,0x9e,
0x7b,0x2e,0x7a,0x83,
0x90,0x1a,0xbd,0xf3
};
uint8_t serp_key[32] = {
0x0a,0xb6,0xfe,0xae,
0xd2,0x50,0xfb,0x94,
0xc2,0xde,0x5f,0x2d,
0xaf,0xad,0x98,0x0c,
0xfa,0xb2,0x5f,0xf4,
0x73,0xf1,0xa0,0xdc,
0xc9,0x5f,0x82,0x93,
0x95,0x27,0xf0,0x21
};
uint8_t second_AES_key[32] = {
0x6c,0xf2,0xfc,0xca,
0xc4,0xdb,0x0e,0xec,
0x2f,0x04,0xd9,0x3e,
0x3c,0xf2,0x4e,0x00,
0xab,0x00,0xe4,0xf4,
0xd5,0x9c,0xf9,0xc5,
0x85,0x72,0xd3,0x3f,
0xbf,0x0e,0xa3,0x76
};

// Keys (Above)

byte back_des_key[24];
uint8_t back_serp_key[32];
unsigned char back_Blwfsh_key[16];
uint8_t back_AES_key[32];
uint8_t back_s_AES_key[32];

void back_serp_k() {
  for (int i = 0; i < 32; i++) {
    back_serp_key[i] = serp_key[i];
  }
}

void rest_serp_k() {
  for (int i = 0; i < 32; i++) {
    serp_key[i] = back_serp_key[i];
  }
}

void back_Bl_k() {
  for (int i = 0; i < 16; i++) {
    back_Blwfsh_key[i] = Blwfsh_key[i];
  }
}

void rest_Bl_k() {
  for (int i = 0; i < 16; i++) {
    Blwfsh_key[i] = back_Blwfsh_key[i];
  }
}

void back_AES_k() {
  for (int i = 0; i < 32; i++) {
    back_AES_key[i] = AES_key[i];
  }
}

void rest_AES_k() {
  for (int i = 0; i < 32; i++) {
    AES_key[i] = back_AES_key[i];
  }
}

void back_3des_k() {
  for (int i = 0; i < 24; i++) {
    back_des_key[i] = des_key[i];
  }
}

void rest_3des_k() {
  for (int i = 0; i < 24; i++) {
    des_key[i] = back_des_key[i];
  }
}

void back_second_AES_key() {
  for (int i = 0; i < 32; i++) {
    back_s_AES_key[i] = second_AES_key[i];
  }
}

void rest_second_AES_key() {
  for (int i = 0; i < 32; i++) {
    second_AES_key[i] = back_s_AES_key[i];
  }
}

void incr_des_key() {
  if (des_key[7] == 255) {
    des_key[7] = 0;
    if (des_key[6] == 255) {
      des_key[6] = 0;
      if (des_key[5] == 255) {
        des_key[5] = 0;
        if (des_key[4] == 255) {
          des_key[4] = 0;
          if (des_key[3] == 255) {
            des_key[3] = 0;
            if (des_key[2] == 255) {
              des_key[2] = 0;
              if (des_key[1] == 255) {
                des_key[1] = 0;
                if (des_key[0] == 255) {
                  des_key[0] = 0;
                } else {
                  des_key[0]++;
                }
              } else {
                des_key[1]++;
              }
            } else {
              des_key[2]++;
            }
          } else {
            des_key[3]++;
          }
        } else {
          des_key[4]++;
        }
      } else {
        des_key[5]++;
      }
    } else {
      des_key[6]++;
    }
  } else {
    des_key[7]++;
  }

  if (des_key[15] == 255) {
    des_key[15] = 0;
    if (des_key[14] == 255) {
      des_key[14] = 0;
      if (des_key[13] == 255) {
        des_key[13] = 0;
        if (des_key[12] == 255) {
          des_key[12] = 0;
          if (des_key[11] == 255) {
            des_key[11] = 0;
            if (des_key[10] == 255) {
              des_key[10] = 0;
              if (des_key[9] == 255) {
                des_key[9] = 0;
                if (des_key[8] == 255) {
                  des_key[8] = 0;
                } else {
                  des_key[8]++;
                }
              } else {
                des_key[9]++;
              }
            } else {
              des_key[10]++;
            }
          } else {
            des_key[11]++;
          }
        } else {
          des_key[12]++;
        }
      } else {
        des_key[13]++;
      }
    } else {
      des_key[14]++;
    }
  } else {
    des_key[15]++;
  }

  if (des_key[23] == 255) {
    des_key[23] = 0;
    if (des_key[22] == 255) {
      des_key[22] = 0;
      if (des_key[21] == 255) {
        des_key[21] = 0;
        if (des_key[20] == 255) {
          des_key[20] = 0;
          if (des_key[19] == 255) {
            des_key[19] = 0;
            if (des_key[18] == 255) {
              des_key[18] = 0;
              if (des_key[17] == 255) {
                des_key[17] = 0;
                if (des_key[16] == 255) {
                  des_key[16] = 0;
                } else {
                  des_key[16]++;
                }
              } else {
                des_key[17]++;
              }
            } else {
              des_key[18]++;
            }
          } else {
            des_key[19]++;
          }
        } else {
          des_key[20]++;
        }
      } else {
        des_key[21]++;
      }
    } else {
      des_key[22]++;
    }
  } else {
    des_key[23]++;
  }
}

void incr_AES_key() {
  if (AES_key[0] == 255) {
    AES_key[0] = 0;
    if (AES_key[1] == 255) {
      AES_key[1] = 0;
      if (AES_key[2] == 255) {
        AES_key[2] = 0;
        if (AES_key[3] == 255) {
          AES_key[3] = 0;
          if (AES_key[4] == 255) {
            AES_key[4] = 0;
            if (AES_key[5] == 255) {
              AES_key[5] = 0;
              if (AES_key[6] == 255) {
                AES_key[6] = 0;
                if (AES_key[7] == 255) {
                  AES_key[7] = 0;
                  if (AES_key[8] == 255) {
                    AES_key[8] = 0;
                    if (AES_key[9] == 255) {
                      AES_key[9] = 0;
                      if (AES_key[10] == 255) {
                        AES_key[10] = 0;
                        if (AES_key[11] == 255) {
                          AES_key[11] = 0;
                          if (AES_key[12] == 255) {
                            AES_key[12] = 0;
                            if (AES_key[13] == 255) {
                              AES_key[13] = 0;
                              if (AES_key[14] == 255) {
                                AES_key[14] = 0;
                                if (AES_key[15] == 255) {
                                  AES_key[15] = 0;
                                } else {
                                  AES_key[15]++;
                                }
                              } else {
                                AES_key[14]++;
                              }
                            } else {
                              AES_key[13]++;
                            }
                          } else {
                            AES_key[12]++;
                          }
                        } else {
                          AES_key[11]++;
                        }
                      } else {
                        AES_key[10]++;
                      }
                    } else {
                      AES_key[9]++;
                    }
                  } else {
                    AES_key[8]++;
                  }
                } else {
                  AES_key[7]++;
                }
              } else {
                AES_key[6]++;
              }
            } else {
              AES_key[5]++;
            }
          } else {
            AES_key[4]++;
          }
        } else {
          AES_key[3]++;
        }
      } else {
        AES_key[2]++;
      }
    } else {
      AES_key[1]++;
    }
  } else {
    AES_key[0]++;
  }
}

void incr_Blwfsh_key() {
  if (Blwfsh_key[0] == 255) {
    Blwfsh_key[0] = 0;
    if (Blwfsh_key[1] == 255) {
      Blwfsh_key[1] = 0;
      if (Blwfsh_key[2] == 255) {
        Blwfsh_key[2] = 0;
        if (Blwfsh_key[3] == 255) {
          Blwfsh_key[3] = 0;
          if (Blwfsh_key[4] == 255) {
            Blwfsh_key[4] = 0;
            if (Blwfsh_key[5] == 255) {
              Blwfsh_key[5] = 0;
              if (Blwfsh_key[6] == 255) {
                Blwfsh_key[6] = 0;
                if (Blwfsh_key[7] == 255) {
                  Blwfsh_key[7] = 0;
                  if (Blwfsh_key[8] == 255) {
                    Blwfsh_key[8] = 0;
                    if (Blwfsh_key[9] == 255) {
                      Blwfsh_key[9] = 0;
                      if (Blwfsh_key[10] == 255) {
                        Blwfsh_key[10] = 0;
                        if (Blwfsh_key[11] == 255) {
                          Blwfsh_key[11] = 0;
                          if (Blwfsh_key[12] == 255) {
                            Blwfsh_key[12] = 0;
                            if (Blwfsh_key[13] == 255) {
                              Blwfsh_key[13] = 0;
                              if (Blwfsh_key[14] == 255) {
                                Blwfsh_key[14] = 0;
                                if (Blwfsh_key[15] == 255) {
                                  Blwfsh_key[15] = 0;
                                } else {
                                  Blwfsh_key[15]++;
                                }
                              } else {
                                Blwfsh_key[14]++;
                              }
                            } else {
                              Blwfsh_key[13]++;
                            }
                          } else {
                            Blwfsh_key[12]++;
                          }
                        } else {
                          Blwfsh_key[11]++;
                        }
                      } else {
                        Blwfsh_key[10]++;
                      }
                    } else {
                      Blwfsh_key[9]++;
                    }
                  } else {
                    Blwfsh_key[8]++;
                  }
                } else {
                  Blwfsh_key[7]++;
                }
              } else {
                Blwfsh_key[6]++;
              }
            } else {
              Blwfsh_key[5]++;
            }
          } else {
            Blwfsh_key[4]++;
          }
        } else {
          Blwfsh_key[3]++;
        }
      } else {
        Blwfsh_key[2]++;
      }
    } else {
      Blwfsh_key[1]++;
    }
  } else {
    Blwfsh_key[0]++;
  }
}

void incr_serp_key() {
  if (serp_key[15] == 255) {
    serp_key[15] = 0;
    if (serp_key[14] == 255) {
      serp_key[14] = 0;
      if (serp_key[13] == 255) {
        serp_key[13] = 0;
        if (serp_key[12] == 255) {
          serp_key[12] = 0;
          if (serp_key[11] == 255) {
            serp_key[11] = 0;
            if (serp_key[10] == 255) {
              serp_key[10] = 0;
              if (serp_key[9] == 255) {
                serp_key[9] = 0;
                if (serp_key[8] == 255) {
                  serp_key[8] = 0;
                  if (serp_key[7] == 255) {
                    serp_key[7] = 0;
                    if (serp_key[6] == 255) {
                      serp_key[6] = 0;
                      if (serp_key[5] == 255) {
                        serp_key[5] = 0;
                        if (serp_key[4] == 255) {
                          serp_key[4] = 0;
                          if (serp_key[3] == 255) {
                            serp_key[3] = 0;
                            if (serp_key[2] == 255) {
                              serp_key[2] = 0;
                              if (serp_key[1] == 255) {
                                serp_key[1] = 0;
                                if (serp_key[0] == 255) {
                                  serp_key[0] = 0;
                                } else {
                                  serp_key[0]++;
                                }
                              } else {
                                serp_key[1]++;
                              }
                            } else {
                              serp_key[2]++;
                            }
                          } else {
                            serp_key[3]++;
                          }
                        } else {
                          serp_key[4]++;
                        }
                      } else {
                        serp_key[5]++;
                      }
                    } else {
                      serp_key[6]++;
                    }
                  } else {
                    serp_key[7]++;
                  }
                } else {
                  serp_key[8]++;
                }
              } else {
                serp_key[9]++;
              }
            } else {
              serp_key[10]++;
            }
          } else {
            serp_key[11]++;
          }
        } else {
          serp_key[12]++;
        }
      } else {
        serp_key[13]++;
      }
    } else {
      serp_key[14]++;
    }
  } else {
    serp_key[15]++;
  }
}

void incr_second_AES_key() {
  if (second_AES_key[0] == 255) {
    second_AES_key[0] = 0;
    if (second_AES_key[1] == 255) {
      second_AES_key[1] = 0;
      if (second_AES_key[2] == 255) {
        second_AES_key[2] = 0;
        if (second_AES_key[3] == 255) {
          second_AES_key[3] = 0;
          if (second_AES_key[4] == 255) {
            second_AES_key[4] = 0;
            if (second_AES_key[5] == 255) {
              second_AES_key[5] = 0;
              if (second_AES_key[6] == 255) {
                second_AES_key[6] = 0;
                if (second_AES_key[7] == 255) {
                  second_AES_key[7] = 0;
                  if (second_AES_key[8] == 255) {
                    second_AES_key[8] = 0;
                    if (second_AES_key[9] == 255) {
                      second_AES_key[9] = 0;
                      if (second_AES_key[10] == 255) {
                        second_AES_key[10] = 0;
                        if (second_AES_key[11] == 255) {
                          second_AES_key[11] = 0;
                          if (second_AES_key[12] == 255) {
                            second_AES_key[12] = 0;
                            if (second_AES_key[13] == 255) {
                              second_AES_key[13] = 0;
                              if (second_AES_key[14] == 255) {
                                second_AES_key[14] = 0;
                                if (second_AES_key[15] == 255) {
                                  second_AES_key[15] = 0;
                                } else {
                                  second_AES_key[15]++;
                                }
                              } else {
                                second_AES_key[14]++;
                              }
                            } else {
                              second_AES_key[13]++;
                            }
                          } else {
                            second_AES_key[12]++;
                          }
                        } else {
                          second_AES_key[11]++;
                        }
                      } else {
                        second_AES_key[10]++;
                      }
                    } else {
                      second_AES_key[9]++;
                    }
                  } else {
                    second_AES_key[8]++;
                  }
                } else {
                  second_AES_key[7]++;
                }
              } else {
                second_AES_key[6]++;
              }
            } else {
              second_AES_key[5]++;
            }
          } else {
            second_AES_key[4]++;
          }
        } else {
          second_AES_key[3]++;
        }
      } else {
        second_AES_key[2]++;
      }
    } else {
      second_AES_key[1]++;
    }
  } else {
    second_AES_key[0]++;
  }
}

int generate_random_number() {
  return esp_random() % 256;
}

size_t hex2bin(void * bin) {
  size_t len, i;
  int x;
  uint8_t * p = (uint8_t * ) bin;
  for (i = 0; i < 32; i++) {
    p[i] = (uint8_t) serp_key[i];
  }
  return 32;
}

int getNum(char ch) {
  int num = 0;
  if (ch >= '0' && ch <= '9') {
    num = ch - 0x30;
  } else {
    switch (ch) {
    case 'A':
    case 'a':
      num = 10;
      break;
    case 'B':
    case 'b':
      num = 11;
      break;
    case 'C':
    case 'c':
      num = 12;
      break;
    case 'D':
    case 'd':
      num = 13;
      break;
    case 'E':
    case 'e':
      num = 14;
      break;
    case 'F':
    case 'f':
      num = 15;
      break;
    default:
      num = 0;
    }
  }
  return num;
}

char getChar(int num) {
  char ch;
  if (num >= 0 && num <= 9) {
    ch = char(num + 48);
  } else {
    switch (num) {
    case 10:
      ch = 'a';
      break;
    case 11:
      ch = 'b';
      break;
    case 12:
      ch = 'c';
      break;
    case 13:
      ch = 'd';
      break;
    case 14:
      ch = 'e';
      break;
    case 15:
      ch = 'f';
      break;
    }
  }
  return ch;
}

void back_keys() {
  back_3des_k();
  back_AES_k();
  back_Bl_k();
  back_serp_k();
  back_second_AES_key();
}

void rest_keys() {
  rest_3des_k();
  rest_AES_k();
  rest_Bl_k();
  rest_serp_k();
  rest_second_AES_key();
}

void clear_variables() {
  input_from_the_ps2_keyboard = "";
  dec_st = "";
  dec_tag = "";
  decract = 0;
  return;
}

// 3DES + AES + Blowfish + Serpent in CBC Mode(Below)

void split_by_ten(char plntxt[], int k, int str_len) {
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte res2[8] = {
    0,
    0
  };

  for (int i = 0; i < 8; i++) {
    if (i + k > str_len - 1)
      break;
    res[i] = byte(plntxt[i + k]);
  }

  for (int i = 0; i < 2; i++) {
    if (i + 8 + k > str_len - 1)
      break;
    res2[i] = byte(plntxt[i + 8 + k]);
  }

  for (int i = 0; i < 8; i++) {
    res[i] ^= array_for_CBC_mode[i];
  }

  for (int i = 0; i < 2; i++) {
    res2[i] ^= array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes(res, res2);
}

void encrypt_iv_for_tdes_aes_blwfsh_serp() {
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte res2[8] = {
    0,
    0
  };

  for (int i = 0; i < 10; i++) {
    array_for_CBC_mode[i] = generate_random_number();
  }

  for (int i = 0; i < 8; i++) {
    res[i] = array_for_CBC_mode[i];
  }

  for (int i = 0; i < 2; i++) {
    res2[i] = array_for_CBC_mode[i + 8];
  }

  encrypt_with_tdes(res, res2);
}

void encrypt_with_tdes(byte res[], byte res2[]) {

  for (int i = 2; i < 8; i++) {
    res2[i] = generate_random_number();
  }

  byte out[8];
  byte out2[8];
  des.tripleEncrypt(out, res, des_key);
  incr_des_key();
  des.tripleEncrypt(out2, res2, des_key);
  incr_des_key();

  char t_aes[16];

  for (int i = 0; i < 8; i++) {
    int b = out[i];
    t_aes[i] = char(b);
  }

  for (int i = 0; i < 8; i++) {
    int b = out2[i];
    t_aes[i + 8] = char(b);
  }

  encrypt_with_AES(t_aes);
}

void encrypt_with_AES(char t_enc[]) {
  uint8_t text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 16; i++) {
    int c = int(t_enc[i]);
    text[i] = c;
  }
  uint8_t cipher_text[16] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  uint32_t AES_key_bit[3] = {
    128,
    192,
    256
  };
  int i = 0;
  aes_context ctx;
  aes_set_key( & ctx, AES_key, AES_key_bit[m]);
  aes_encrypt_block( & ctx, cipher_text, text);
  /*
  for (int i=0; i<16; i++) {
    if(cipher_text[i]<16)
      Serial.print("0");
    Serial.print(cipher_text[i],HEX);
  }
  Serial.println();
  */
  incr_AES_key();
  unsigned char first_eight[8];
  unsigned char second_eight[8];
  for (int i = 0; i < 8; i++) {
    first_eight[i] = (unsigned char) cipher_text[i];
    second_eight[i] = (unsigned char) cipher_text[i + 8];
  }
  encrypt_with_Blowfish(first_eight, false);
  encrypt_with_Blowfish(second_eight, true);
  encrypt_with_serpent();
}

void encrypt_with_Blowfish(unsigned char inp[], bool lrside) {
  unsigned char plt[8];
  for (int i = 0; i < 8; i++)
    plt[i] = inp[i];
  blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
  blowfish.Encrypt(plt, plt, sizeof(plt));
  String encrypted_with_blowfish;
  for (int i = 0; i < 8; i++) {
    if (lrside == false)
      pass_to_serp[i] = int(plt[i]);
    if (lrside == true)
      pass_to_serp[i + 8] = int(plt[i]);
  }
  incr_Blwfsh_key();
}

void encrypt_with_serpent() {
  uint8_t ct1[32], pt1[32], key[64];
  int plen, clen, b, j;
  serpent_key skey;
  serpent_blk ct2;
  uint32_t * p;

  for (b = 0; b < 1; b++) {
    hex2bin(key);

    // set key
    memset( & skey, 0, sizeof(skey));
    p = (uint32_t * ) & skey.x[0][0];

    serpent_setkey( & skey, key);

    for (int i = 0; i < 16; i++) {
      ct2.b[i] = pass_to_serp[i];
    }
    serpent_encrypt(ct2.b, & skey, SERPENT_ENCRYPT);
    incr_serp_key();
    /*
    for (int i = 0; i < 16; i++) {
      if (ct2.b[i] < 16)
        Serial.print("0");
      Serial.print(ct2.b[i], HEX);
    }
    */
    for (int i = 0; i < 16; i++) {
      if (decract > 0) {
        if (i < 10) {
          array_for_CBC_mode[i] = byte(int(ct2.b[i]));
        }
      }
      if (ct2.b[i] < 16)
        dec_st += "0";
      dec_st += String(ct2.b[i], HEX);
    }
    decract++;
  }
}

void split_for_decryption(char ct[], int ct_len, int p) {
  int br = false;
  byte res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  byte prev_res[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  };
  for (int i = 0; i < 32; i += 2) {
    if (i + p > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i] = 0;
    } else {
      if (ct[i + p] != 0 && ct[i + p + 1] != 0)
        res[i / 2] = 16 * getNum(ct[i + p]) + getNum(ct[i + p + 1]);
      if (ct[i + p] != 0 && ct[i + p + 1] == 0)
        res[i / 2] = 16 * getNum(ct[i + p]);
      if (ct[i + p] == 0 && ct[i + p + 1] != 0)
        res[i / 2] = getNum(ct[i + p + 1]);
      if (ct[i + p] == 0 && ct[i + p + 1] == 0)
        res[i / 2] = 0;
    }
  }

  for (int i = 0; i < 32; i += 2) {
    if (i + p - 32 > ct_len - 1) {
      br = true;
      break;
    }
    if (i == 0) {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i] = 0;
    } else {
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]) + getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] != 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 16 * getNum(ct[i + p - 32]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] != 0)
        prev_res[i / 2] = getNum(ct[i + p - 32 + 1]);
      if (ct[i + p - 32] == 0 && ct[i + p - 32 + 1] == 0)
        prev_res[i / 2] = 0;
    }
  }

  if (br == false) {
    if (decract > 10) {
      for (int i = 0; i < 10; i++) {
        array_for_CBC_mode[i] = prev_res[i];
      }
    }
    uint8_t ct1[32], pt1[32], key[64];
    int plen, clen, i, j;
    serpent_key skey;
    serpent_blk ct2;
    uint32_t * p;

    for (i = 0; i < 1; i++) {
      hex2bin(key);

      // set key
      memset( & skey, 0, sizeof(skey));
      p = (uint32_t * ) & skey.x[0][0];

      serpent_setkey( & skey, key);

      for (int i = 0; i < 16; i++)
        ct2.b[i] = res[i];
      /*
      Serial.printf ("\n\n");
      for(int i = 0; i<16; i++){
      Serial.printf("%x", ct2.b[i]);
      Serial.printf(" ");
      */
    }
    //Serial.printf("\n");
    serpent_encrypt(ct2.b, & skey, SERPENT_DECRYPT);
    incr_serp_key();
    unsigned char lh[8];
    unsigned char rh[8];
    for (int i = 0; i < 8; i++) {
      lh[i] = (unsigned char) int(ct2.b[i]);
      rh[i] = (unsigned char) int(ct2.b[i + 8]);
    }
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(lh, lh, sizeof(lh));
    incr_Blwfsh_key();
    blowfish.SetKey(Blwfsh_key, sizeof(Blwfsh_key));
    blowfish.Decrypt(rh, rh, sizeof(rh));
    incr_Blwfsh_key();
    uint8_t ret_text[16] = {
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    };
    uint8_t cipher_text[16] = {
      0
    };
    for (int i = 0; i < 8; i++) {
      int c = int(lh[i]);
      cipher_text[i] = c;
    }
    for (int i = 0; i < 8; i++) {
      int c = int(rh[i]);
      cipher_text[i + 8] = c;
    }
    /*
    for (int i=0; i<16; i++) {
      if(cipher_text[i]<16)
        Serial.print("0");
      Serial.print(cipher_text[i],HEX);
    }
    Serial.println();
    */
    uint32_t AES_key_bit[3] = {
      128,
      192,
      256
    };
    aes_context ctx;
    aes_set_key( & ctx, AES_key, AES_key_bit[m]);
    aes_decrypt_block( & ctx, ret_text, cipher_text);
    incr_AES_key();

    byte res[8];
    byte res2[8];

    for (int i = 0; i < 8; i++) {
      res[i] = int(ret_text[i]);
      res2[i] = int(ret_text[i + 8]);
    }

    byte out[8];
    byte out2[8];
    des.tripleDecrypt(out, res, des_key);
    incr_des_key();
    des.tripleDecrypt(out2, res2, des_key);
    incr_des_key();
    /*
        Serial.println();
        for (int i=0; i<8; i++) {
          if(out[i]<8)
            Serial.print("0");
          Serial.print(out[i],HEX);
        }

        for (int i=0; i<8; i++) {
          if(out2[i]<8)
            Serial.print("0");
          Serial.print(out[i],HEX);
        }
        Serial.println();
    */

    if (decract > 2) {
      for (int i = 0; i < 8; i++) {
        out[i] ^= array_for_CBC_mode[i];
      }

      for (int i = 0; i < 2; i++) {
        out2[i] ^= array_for_CBC_mode[i + 8];
      }

      if (decrypt_tag == false) {

        for (i = 0; i < 8; ++i) {
          if (out[i] > 0)
            dec_st += char(out[i]);
        }

        for (i = 0; i < 2; ++i) {
          if (out2[i] > 0)
            dec_st += char(out2[i]);
        }

      } else {
        for (i = 0; i < 8; ++i) {
          if (out[i] < 0x10)
            dec_tag += "0";
          dec_tag += String(out[i], HEX);
        }

        for (i = 0; i < 2; ++i) {
          if (out2[i] < 0x10)
            dec_tag += "0";
          dec_tag += String(out2[i], HEX);
        }
      }
    }

    if (decract == -1) {
      for (i = 0; i < 8; ++i) {
        array_for_CBC_mode[i] = out[i];
      }

      for (i = 0; i < 2; ++i) {
        array_for_CBC_mode[i + 8] = out2[i];;
      }
    }
    decract++;
  }
}

void encr_hash_for_tdes_aes_blf_srp(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp();
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  hmac.doUpdate(input_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  int p = 0;
  char hmacchar[30];
  for (int i = 0; i < 30; i++) {
    hmacchar[i] = char(authCode[i]);
  }

  for (int i = 0; i < 3; i++) {
    split_by_ten(hmacchar, p, 100);
    p += 10;
  }
  rest_keys();
}

void encrypt_with_TDES_AES_Blowfish_Serp(String input) {
  back_keys();
  clear_variables();
  encrypt_iv_for_tdes_aes_blwfsh_serp();
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    split_by_ten(input_arr, p, str_len);
    p += 10;
  }
  rest_keys();
}

void decrypt_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = false;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void decrypt_tag_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  while (ct_len > ext) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

void encrypt_string_with_tdes_aes_blf_srp(String input) {
  encrypt_with_TDES_AES_Blowfish_Serp(input);
  String td_aes_bl_srp_ciphertext = dec_st;
  encr_hash_for_tdes_aes_blf_srp(input);
  dec_st += td_aes_bl_srp_ciphertext;
}

void decrypt_string_with_TDES_AES_Blowfish_Serp(String ct) {
  back_keys();
  clear_variables();
  decrypt_tag = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  decract = -1;
  for (int i = 0; i < 128; i += 32) {
    split_for_decryption(ct_array, ct_len, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();

  back_keys();
  dec_st = "";
  decrypt_tag = false;
  int ct_len1 = ct.length() + 1;
  char ct_array1[ct_len1];
  ct.toCharArray(ct_array1, ct_len1);
  ext = 128;
  decract = -1;
  while (ct_len1 > ext) {
    split_for_decryption(ct_array1, ct_len1, 0 + ext);
    ext += 32;
    decract += 10;
  }
  rest_keys();
}

// 3DES + AES + Blowfish + Serpent in CBC Mode (Above)

bool verify_integrity() {
  int str_lentg = dec_st.length() + 1;
  char char_arraytg[str_lentg];
  dec_st.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_arraytg);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;

  for (byte i = 0; i < SHA256HMAC_SIZE - 2; i++) {
    if (authCode[i] < 0x10) {
      res_hash += 0;
    } {
      res_hash += String(authCode[i], HEX);
    }
  }
  /*
  Serial.println(dec_st);
  Serial.println(dec_tag);
  Serial.println(res_hash);
  */
  return dec_tag.equals(res_hash);
}

bool verify_integrity_thirty_two() {
  int str_lentg = dec_st.length() + 1;
  char char_arraytg[str_lentg];
  dec_st.toCharArray(char_arraytg, str_lentg);
  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  hmac.doUpdate(char_arraytg);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  String res_hash;

  for (byte i = 0; i < SHA256HMAC_SIZE; i++) {
    if (authCode[i] < 0x10) {
      res_hash += 0;
    } {
      res_hash += String(authCode[i], HEX);
    }
  }

  return dec_tag.equals(res_hash);
}

void press_any_key_to_continue() {
  rec_d = false;
  delay(2);
  while (rec_d == false) {
    delay(4);
    get_key_from_ps_keyb();
  }
  delay(12);
  data_from_keyboard = 0;
}

void get_key_from_ps_keyb(){
   code = keyboard.available();
   if (code > 0) {
     code = keyboard.read();
     //Serial.print("Value ");
     //Serial.print(code, HEX);
     if (code == 277) { // Leftwards Arrow
       data_from_keyboard = 129;
       rec_d = true;
     }
     if (code == 278) { // Rightwards Arrow
       data_from_keyboard = 130;
       rec_d = true;
     }
     if (code == 279) { // Upwards Arrow
       data_from_keyboard = 131;
       rec_d = true;
     }
     if (code == 280) { // Downwards Arrow
       data_from_keyboard = 132;
       rec_d = true;
     }
     code = keymap.remapKey(code);
     if (code > 0) {
       if ((code & 0xFF)) {
         if ((code & 0xFF) == 27) { // Esc
           data_from_keyboard = 27;
           rec_d = true;
         } else if ((code & 0xFF) == 13) { // Enter
            data_from_keyboard = 13;
            rec_d = true;
         } else if ((code & 0xFF) == 8) { // Backspace
           data_from_keyboard = 8;
           rec_d = true;
         } else {
           data_from_keyboard = code & 0xFF;
           rec_d = true;
         }
       }
   }
  }
}

void set_stuff_for_input(String blue_inscr) {
  rec_d = false;
  curr_key = 65;
  tft.fillScreen(0x0000);
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.setCursor(2, 0);
  tft.print("Char'");
  tft.setCursor(74, 0);
  tft.print("'");
  disp();
  tft.setCursor(0, 20);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  tft.print(blue_inscr);
  tft.fillRect(155, 0, 4, 128, stripe_on_the_right_color);
}

void disp() {
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.setTextColor(0x07e0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.fillRect(125, 0, 22, 14, 0x0000);
  tft.setCursor(125, 0);
  tft.print(hexstr);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 32);
  tft.print(input_from_the_ps2_keyboard);
}

void ps2_input_from_the_ps2_keyboard() {
  finish_input = false;
  rec_d = false;
  byte inp_frm_cntr_and_ps2_kbrd = 0;
  while (finish_input == false) {
    inp_frm_cntr_and_ps2_kbrd = get_inp_fr_ps_keybrd();
    if (inp_frm_cntr_and_ps2_kbrd > 0) {
      if (inp_frm_cntr_and_ps2_kbrd > 31 && inp_frm_cntr_and_ps2_kbrd < 127) {
        curr_key = inp_frm_cntr_and_ps2_kbrd;
        input_from_the_ps2_keyboard += char(curr_key);
        //Serial.println(input_from_the_ps2_keyboard);
        disp();
      }

      if (inp_frm_cntr_and_ps2_kbrd == 27) {
        act = false;
        finish_input = true;
      }

      if (inp_frm_cntr_and_ps2_kbrd == 13) {
        finish_input = true;
      }

      if (inp_frm_cntr_and_ps2_kbrd == 130) {
        curr_key++;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (inp_frm_cntr_and_ps2_kbrd == 129) {
        curr_key--;
        disp();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (inp_frm_cntr_and_ps2_kbrd == 131 || inp_frm_cntr_and_ps2_kbrd == 133) {
        input_from_the_ps2_keyboard += char(curr_key);
        //Serial.println(input_from_the_ps2_keyboard);
        disp();
      }

      if (inp_frm_cntr_and_ps2_kbrd == 132 || inp_frm_cntr_and_ps2_kbrd == 8) {
        if (input_from_the_ps2_keyboard.length() > 0)
          input_from_the_ps2_keyboard.remove(input_from_the_ps2_keyboard.length() - 1, 1);
        //Serial.println(input_from_the_ps2_keyboard);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(input_from_the_ps2_keyboard);
        disp();

      }
      //Serial.println(inp_frm_cntr_and_ps2_kbrd);
      inp_frm_cntr_and_ps2_kbrd = 0;
    }
    delayMicroseconds(400);
  }
}

void disp_stars() {
  tft.setTextSize(2);
  tft.setTextColor(0xffff);
  tft.fillRect(62, 0, 10, 16, 0x0000);
  tft.setCursor(62, 0);
  tft.print(char(curr_key));
  tft.setTextColor(0x07e0);
  String hexstr;
  if (curr_key < 16)
    hexstr += 0;
  hexstr += String(curr_key, HEX);
  hexstr.toUpperCase();
  tft.fillRect(125, 0, 22, 14, 0x0000);
  tft.setCursor(125, 0);
  tft.print(hexstr);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 32);
  int plnt = input_from_the_ps2_keyboard.length();
  String stars = "";
  for (int i = 0; i < plnt; i++) {
    stars += "*";
  }
  tft.print(stars);
}

void starred_ps2_input_from_the_ps2_keyboard() {
  finish_input = false;
  rec_d = false;
  byte inp_frm_cntr_and_ps2_kbrd = 0;
  while (finish_input == false) {
    inp_frm_cntr_and_ps2_kbrd = get_inp_fr_ps_keybrd();
    if (inp_frm_cntr_and_ps2_kbrd > 0) {
      if (inp_frm_cntr_and_ps2_kbrd > 31 && inp_frm_cntr_and_ps2_kbrd < 127) {
        curr_key = inp_frm_cntr_and_ps2_kbrd;
        input_from_the_ps2_keyboard += char(curr_key);
        //Serial.println(input_from_the_ps2_keyboard);
        disp_stars();
      }

      if (inp_frm_cntr_and_ps2_kbrd == 27) {
        act = false;
        finish_input = true;
      }

      if (inp_frm_cntr_and_ps2_kbrd == 13) {
        finish_input = true;
      }

      if (inp_frm_cntr_and_ps2_kbrd == 130) {
        curr_key++;
        disp_stars();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (inp_frm_cntr_and_ps2_kbrd == 129) {
        curr_key--;
        disp_stars();
        if (curr_key < 32)
          curr_key = 126;

        if (curr_key > 126)
          curr_key = 32;
      }

      if (inp_frm_cntr_and_ps2_kbrd == 131 || inp_frm_cntr_and_ps2_kbrd == 133) {
        input_from_the_ps2_keyboard += char(curr_key);
        //Serial.println(input_from_the_ps2_keyboard);
        disp_stars();
      }

      if (inp_frm_cntr_and_ps2_kbrd == 132 || inp_frm_cntr_and_ps2_kbrd == 8) {
        if (input_from_the_ps2_keyboard.length() > 0)
          input_from_the_ps2_keyboard.remove(input_from_the_ps2_keyboard.length() - 1, 1);
        //Serial.println(input_from_the_ps2_keyboard);
        tft.fillRect(0, 32, 155, 96, 0x0000);
        //Serial.println(input_from_the_ps2_keyboard);
        disp_stars();

      }
      //Serial.println(inp_frm_cntr_and_ps2_kbrd);
      inp_frm_cntr_and_ps2_kbrd = 0;
    }
    delayMicroseconds(400);
  }
}

void disp_centered_text(String t_disp, int y){
  if (t_disp.length() < 27){
    int16_t x1, y1;
    uint16_t w, h;
    tft.getTextBounds(t_disp, 160, 0, &x1, &y1, &w, &h);
    tft.setCursor(80 - (w / 2), y);
    tft.print(t_disp);
  }
  else{
    tft.setCursor(0, y);
    tft.print(t_disp);
  }
}

void disp_centered_text_b_w(String text, int h) {
  int16_t x1;
  int16_t y1;
  uint16_t width;
  uint16_t height;

  tft.getTextBounds(text, 0, 0, & x1, & y1, & width, & height);
  tft.setTextColor(0x0882);
  tft.setCursor((160 - width) / 2, h - 1);
  tft.print(text);
  tft.setCursor((160 - width) / 2, h + 1);
  tft.print(text);
  tft.setCursor(((160 - width) / 2) - 1, h);
  tft.print(text);
  tft.setCursor(((160 - width) / 2) + 1, h);
  tft.print(text);
  tft.setTextColor(0xf7de);
  tft.setCursor((160 - width) / 2, h);
  tft.print(text);
}

// Functions that work with files in Firebase (Below)

String read_file(String filename){
  if(Firebase.getString(fbdo, filename.c_str())){
    return (fbdo.to<String>());
  }
  else
    return "-1";
}

void write_to_file_with_overwrite(String filename, String content){
  if (!Firebase.set(fbdo, filename.c_str(), content.c_str())){
    tft.fillScreen(0x0000);
    tft.setTextColor(0xf800);
    tft.setCursor(0, 0);
    tft.print("Failed To Create File!");
    delay(2000);
    tft.fillScreen(0x0000);    
  }
}

void delete_file(String filename){
  if(!Firebase.deleteNode(fbdo, filename.c_str())){
    tft.fillScreen(0x0000);
    tft.setTextColor(0xf800);
    tft.setCursor(0, 0);
    tft.print("Failed To Delete File!");
    delay(2000);
    tft.fillScreen(0x0000);
  }
}

// Functions for Logins (Below)

void select_login(byte what_to_do_with_it) {
  // 0 - Add login
  // 1 - Edit login
  // 2 - Delete login
  // 3 - View login
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;
  
  header_for_select_login(what_to_do_with_it);
  display_title_from_login_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    byte input_data = get_inp_fr_ps_keybrd();
    if (input_data > 0) {
      

      if (input_data == 130)
        curr_key++;

      if (input_data == 129)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (input_data == 13) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0  && continue_to_next == false) { continue_to_next = true;
          byte inptsrc = input_source_for_data_in_flash();
          if (inptsrc == 1)
            add_login_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            add_login_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 1  && continue_to_next == false) { continue_to_next = true;
          byte inptsrc = input_source_for_data_in_flash();
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          if (inptsrc == 1)
            edit_login_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            edit_login_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 2  && continue_to_next == false) { continue_to_next = true;
          delete_login(chsn_slot);
        }
        if (what_to_do_with_it == 3  && continue_to_next == false) { continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_login(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (input_data == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(DELAY_FOR_SLOTS);
      header_for_select_login(what_to_do_with_it);
      display_title_from_login_without_integrity_verification();
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_login(byte what_to_do_with_it) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  if (what_to_do_with_it == 0){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Login to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2){
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Login " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_login_without_integrity_verification() {
  tft.setTextSize(1);
  String encrypted_title = read_file("/L" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 20);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 20);
  }
}

void add_login_from_keyboard_and_encdr(int chsn_slot) {
  enter_title_for_login(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_login(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    enter_username_for_login(chsn_slot, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_username_for_login(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Username");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    enter_password_for_login(chsn_slot, entered_title, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_password_for_login(int chsn_slot, String entered_title, String entered_username) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Password");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    enter_website_for_login(chsn_slot, entered_title, entered_username, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_website_for_login(int chsn_slot, String entered_title, String entered_username, String entered_password) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Website");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    write_login_to_flash(chsn_slot, entered_title, entered_username, entered_password, input_from_the_ps2_keyboard);
  }
  return;
}

void add_login_from_serial(int chsn_slot) {
  get_title_for_login_from_serial(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void get_title_for_login_from_serial(int chsn_slot) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Title");
    Serial.println("\nPaste the title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    get_username_for_login_from_serial(chsn_slot, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_username_for_login_from_serial(int chsn_slot, String entered_title) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Username");
    Serial.println("\nPaste the username here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    get_password_for_login_from_serial(chsn_slot, entered_title, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_password_for_login_from_serial(int chsn_slot, String entered_title, String entered_username) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Password");
    Serial.println("\nPaste the password here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    get_website_for_login_from_serial(chsn_slot, entered_title, entered_username, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_website_for_login_from_serial(int chsn_slot, String entered_title, String entered_username, String entered_password) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Website");
    Serial.println("\nPaste the website here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    write_login_to_flash(chsn_slot, entered_title, entered_username, entered_password, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void write_login_to_flash(int chsn_slot, String entered_title, String entered_username, String entered_password, String entered_website) {
  /*
  Serial.println();
  Serial.println(chsn_slot);
  Serial.println(entered_title);
  Serial.println(entered_username);
  Serial.println(entered_password);
  Serial.println(entered_website);
  */
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Adding Login");
  tft.setCursor(0, 10);
  tft.print("To The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_username);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_usn", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_password);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_psw", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_wbs", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_username + entered_password + entered_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_login_and_tag(int chsn_slot, String new_password) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing Login");
  tft.setCursor(0, 10);
  tft.print("In The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_password);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_psw", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_usn"));
  String decrypted_username = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_wbs"));
  String decrypted_website = dec_st;

  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_username + new_password + decrypted_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_login_from_keyboard_and_encdr(int chsn_slot) {
  if (read_file("/L" + String(chsn_slot) + "_psw") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_psw"));
    String old_password = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Password");
    input_from_the_ps2_keyboard = old_password;
    disp();
    ps2_input_from_the_ps2_keyboard();
    if (act == true) {
      update_login_and_tag(chsn_slot, input_from_the_ps2_keyboard);
    }
  }
  return;
}

void edit_login_from_serial(int chsn_slot) {
  if (read_file("/L" + String(chsn_slot) + "_psw") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
    press_any_key_to_continue();
  } else {
    bool cont_to_next = false;
    while (cont_to_next == false) {
      disp_paste_smth_inscr("New Password");
      Serial.println("\nPaste new password here:");
      bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
      if (canc_op == true)
        break;
      update_login_and_tag(chsn_slot, Serial.readString());
      cont_to_next = true;
      break;
    }
  }
  return;
}

void delete_login(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting Login");
  tft.setCursor(0, 10);
  tft.print("From The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  delete_file("/L" + String(chsn_slot) + "_tag");
  delete_file("/L" + String(chsn_slot) + "_ttl");
  delete_file("/L" + String(chsn_slot) + "_usn");
  delete_file("/L" + String(chsn_slot) + "_psw");
  delete_file("/L" + String(chsn_slot) + "_wbs");
  clear_variables();
  call_main_menu();
  return;
}

void view_login(int chsn_slot) {
  if (read_file("/L" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_usn"));
    String decrypted_username = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_psw"));
    String decrypted_password = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_wbs"));
    String decrypted_website = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/L" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_username + decrypted_password + decrypted_website;
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Username:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_username);
      tft.setTextColor(current_inact_clr);
      tft.print("Password:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_password);
      tft.setTextColor(current_inact_clr);
      tft.print("Website:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_website);
      tft.setTextSize(1);
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, current_inact_clr);
      disp_centered_text(succs_ver_inscr, 120);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Username:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_username);
      tft.setTextColor(current_inact_clr);
      tft.print("Password:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_password);
      tft.setTextColor(current_inact_clr);
      tft.print("Website:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_website);
      tft.setTextSize(1);
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, five_six_five_red_color);
      disp_centered_text(faild_ver_inscr, 120);
    }
    act = false;
    up_or_encdr_bttn_to_print();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Username:\"");
      Serial.print(decrypted_username);
      Serial.println("\"");
      Serial.print("Password:\"");
      Serial.print(decrypted_password);
      Serial.println("\"");
      Serial.print("Website:\"");
      Serial.print(decrypted_website);
      Serial.println("\"");
      if (login_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

// Functions for Logins (Above)

// Functions for Credit Cards (Below)

void select_credit_card(byte what_to_do_with_it) {
  // 0 - Add credit_card
  // 1 - Edit credit_card
  // 2 - Delete credit_card
  // 3 - View credit_card
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;
  
  header_for_select_credit_card(what_to_do_with_it);
  display_title_from_credit_card_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    byte input_data = get_inp_fr_ps_keybrd();
    if (input_data > 0) {
      

      if (input_data == 130)
        curr_key++;

      if (input_data == 129)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (input_data == 13) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0  && continue_to_next == false) { continue_to_next = true;
          byte inptsrc = input_source_for_data_in_flash();
          if (inptsrc == 1)
            add_credit_card_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            add_credit_card_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 1  && continue_to_next == false) { continue_to_next = true;
          byte inptsrc = input_source_for_data_in_flash();
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          if (inptsrc == 1)
            edit_credit_card_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            edit_credit_card_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 2  && continue_to_next == false) { continue_to_next = true;
          delete_credit_card(chsn_slot);
        }
        if (what_to_do_with_it == 3  && continue_to_next == false) { continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_credit_card(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (input_data == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(DELAY_FOR_SLOTS);
      header_for_select_credit_card(what_to_do_with_it);
      display_title_from_credit_card_without_integrity_verification();
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_credit_card(byte what_to_do_with_it) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  if (what_to_do_with_it == 0){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Card to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Credit Card " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2){
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Credit Card " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Credit Card " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_credit_card_without_integrity_verification() {
  tft.setTextSize(1);
  String encrypted_title = read_file("/C" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 20);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 20);
  }
}

void add_credit_card_from_keyboard_and_encdr(int chsn_slot) {
  enter_title_for_credit_card(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_credit_card(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    enter_cardholder_for_credit_card(chsn_slot, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_cardholder_for_credit_card(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Cardholder Name");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    enter_card_number_for_credit_card(chsn_slot, entered_title, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_card_number_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Card Number");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    enter_expiry_for_credit_card(chsn_slot, entered_title, entered_cardholder, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_expiry_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Expiration Date");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    enter_cvn_for_credit_card(chsn_slot, entered_title, entered_cardholder, entered_card_number, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_cvn_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter CVN");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    enter_pin_for_credit_card(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_pin_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter PIN");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    enter_zip_code_for_credit_card(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_zip_code_for_credit_card(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter ZIP Code");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    write_credit_card_to_flash(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, entered_pin, input_from_the_ps2_keyboard);
  }
  return;
}

void add_credit_card_from_serial(int chsn_slot) {
  get_title_for_credit_card_from_serial(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void get_title_for_credit_card_from_serial(int chsn_slot) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Title");
    Serial.println("\nPaste the title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    get_cardholder_name_for_credit_card_from_serial(chsn_slot, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_cardholder_name_for_credit_card_from_serial(int chsn_slot, String entered_title) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Cardholder Name");
    Serial.println("\nPaste the cardholder name here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    get_card_number_for_credit_card_from_serial(chsn_slot, entered_title, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_card_number_for_credit_card_from_serial(int chsn_slot, String entered_title, String entered_cardholder) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Card Number");
    Serial.println("\nPaste the card number here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    get_expiration_date_for_credit_card_from_serial(chsn_slot, entered_title, entered_cardholder, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_expiration_date_for_credit_card_from_serial(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Expiration Date");
    Serial.println("\nPaste the expiration date here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    get_cvn_for_credit_card_from_serial(chsn_slot, entered_title, entered_cardholder, entered_card_number, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_cvn_for_credit_card_from_serial(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("CVN");
    Serial.println("\nPaste the CVN here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    get_pin_for_credit_card_from_serial(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_pin_for_credit_card_from_serial(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("PIN");
    Serial.println("\nPaste the PIN here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    get_zip_code_for_credit_card_from_serial(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_zip_code_for_credit_card_from_serial(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("ZIP Code");
    Serial.println("\nPaste the ZIP code here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    write_credit_card_to_flash(chsn_slot, entered_title, entered_cardholder, entered_card_number, entered_expiry, entered_cvn, entered_pin, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void write_credit_card_to_flash(int chsn_slot, String entered_title, String entered_cardholder, String entered_card_number, String entered_expiry, String entered_cvn, String entered_pin, String entered_zip_code) {
  /*
  Serial.println();
  Serial.println(chsn_slot);
  Serial.println(entered_title);
  Serial.println(entered_cardholder);
  Serial.println(entered_card_number);
  Serial.println(entered_expiry);
  */
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Adding Credit Card");
  tft.setCursor(0, 10);
  tft.print("To The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_cardholder);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_hld", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_card_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_nmr", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_expiry);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_exp", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_cvn);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_cvn", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_pin);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_pin", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_zip_code);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_zip", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_cardholder + entered_card_number + entered_expiry + entered_cvn + entered_pin + entered_zip_code);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_credit_card_and_tag(int chsn_slot, String new_pin) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing Credit Card");
  tft.setCursor(0, 10);
  tft.print("In The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_pin);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_pin", dec_st);
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_hld"));
  String decrypted_cardholder = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_nmr"));
  String decrypted_card_number = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_exp"));
  String decrypted_expiry = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_cvn"));
  String decrypted_cvn = dec_st;
  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_zip"));
  String decrypted_zip_code = dec_st;
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_expiry + decrypted_cvn + new_pin + decrypted_zip_code);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/C" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_credit_card_from_keyboard_and_encdr(int chsn_slot) {
  if (read_file("/C" + String(chsn_slot) + "_pin") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_pin"));
    String old_pin = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit PIN");
    input_from_the_ps2_keyboard = old_pin;
    disp();
    ps2_input_from_the_ps2_keyboard();
    if (act == true) {
      update_credit_card_and_tag(chsn_slot, input_from_the_ps2_keyboard);
    }
  }
  return;
}

void edit_credit_card_from_serial(int chsn_slot) {
  if (read_file("/C" + String(chsn_slot) + "_pin") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
    press_any_key_to_continue();
  } else {
    bool cont_to_next = false;
    while (cont_to_next == false) {
      disp_paste_smth_inscr("New PIN");
      Serial.println("\nPaste new PIN here:");
      bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
      if (canc_op == true)
        break;
      update_credit_card_and_tag(chsn_slot, Serial.readString());
      cont_to_next = true;
      break;
    }
  }
  return;
}

void delete_credit_card(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting Credit Card");
  tft.setCursor(0, 10);
  tft.print("From The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  delete_file("/C" + String(chsn_slot) + "_tag");
  delete_file("/C" + String(chsn_slot) + "_ttl");
  delete_file("/C" + String(chsn_slot) + "_hld");
  delete_file("/C" + String(chsn_slot) + "_nmr");
  delete_file("/C" + String(chsn_slot) + "_exp");
  delete_file("/C" + String(chsn_slot) + "_cvn");
  delete_file("/C" + String(chsn_slot) + "_pin");
  delete_file("/C" + String(chsn_slot) + "_zip");
  clear_variables();
  call_main_menu();
  return;
}

void view_credit_card(int chsn_slot) {
  if (read_file("/C" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_hld"));
    String decrypted_cardholder = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_nmr"));
    String decrypted_card_number = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_exp"));
    String decrypted_expiry = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_cvn"));
    String decrypted_cvn = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_pin"));
    String decrypted_pin = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_zip"));
    String decrypted_zip_code = dec_st;
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/C" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_cardholder + decrypted_card_number + decrypted_expiry + decrypted_cvn + decrypted_pin + decrypted_zip_code;
    bool credit_card_integrity = verify_integrity();

    if (credit_card_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Cardholder Name:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_cardholder);
      tft.setTextColor(current_inact_clr);
      tft.print("Card Number:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_card_number);
      tft.setTextColor(current_inact_clr);
      tft.print("Expiration Date:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_expiry);
      tft.setTextColor(current_inact_clr);
      tft.print("CVN:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_cvn);
      tft.setTextColor(current_inact_clr);
      tft.print("PIN:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_pin);
      tft.setTextColor(current_inact_clr);
      tft.print("ZIP Code:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_zip_code);
      tft.setTextSize(1);
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, current_inact_clr);
      disp_centered_text(succs_ver_inscr, 120);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Cardholder Name:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_cardholder);
      tft.setTextColor(current_inact_clr);
      tft.print("Card Number:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_card_number);
      tft.setTextColor(current_inact_clr);
      tft.print("Expiration Date:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_expiry);
      tft.setTextColor(current_inact_clr);
      tft.print("CVN:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_cvn);
      tft.setTextColor(current_inact_clr);
      tft.print("PIN:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_pin);
      tft.setTextColor(current_inact_clr);
      tft.print("ZIP Code:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_zip_code);
      tft.setTextSize(1);
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, five_six_five_red_color);
      disp_centered_text(faild_ver_inscr, 120);
    }
    act = false;
    up_or_encdr_bttn_to_print();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Cardholder Name:\"");
      Serial.print(decrypted_cardholder);
      Serial.println("\"");
      Serial.print("Card Number:\"");
      Serial.print(decrypted_card_number);
      Serial.println("\"");
      Serial.print("Expiration Date:\"");
      Serial.print(decrypted_expiry);
      Serial.println("\"");
      Serial.print("CVN:\"");
      Serial.print(decrypted_cvn);
      Serial.println("\"");
      Serial.print("PIN:\"");
      Serial.print(decrypted_pin);
      Serial.println("\"");
      Serial.print("ZIP Code:\"");
      Serial.print(decrypted_zip_code);
      Serial.println("\"");
      if (credit_card_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

// Functions for Credit Cards (Above)

// Functions for Notes (Below)

void select_note(byte what_to_do_with_it) {
  // 0 - Add note
  // 1 - Edit note
  // 2 - Delete note
  // 3 - View note
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;
  
  header_for_select_note(what_to_do_with_it);
  display_title_from_note_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    byte input_data = get_inp_fr_ps_keybrd();
    if (input_data > 0) {
      

      if (input_data == 130)
        curr_key++;

      if (input_data == 129)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (input_data == 13) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0  && continue_to_next == false) { continue_to_next = true;
          byte inptsrc = input_source_for_data_in_flash();
          if (inptsrc == 1)
            add_note_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            add_note_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 1  && continue_to_next == false) { continue_to_next = true;
          byte inptsrc = input_source_for_data_in_flash();
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          if (inptsrc == 1)
            edit_note_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            edit_note_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 2  && continue_to_next == false) { continue_to_next = true;
          delete_note(chsn_slot);
        }
        if (what_to_do_with_it == 3  && continue_to_next == false) { continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_note(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (input_data == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(DELAY_FOR_SLOTS);
      header_for_select_note(what_to_do_with_it);
      display_title_from_note_without_integrity_verification();
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_note(byte what_to_do_with_it) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  if (what_to_do_with_it == 0){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Note to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Note " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2){
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Note " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Note " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_note_without_integrity_verification() {
  tft.setTextSize(1);
  String encrypted_title = read_file("/N" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 20);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 20);
  }
}

void add_note_from_keyboard_and_encdr(int chsn_slot) {
  enter_title_for_note(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_note(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    enter_content_for_note(chsn_slot, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_content_for_note(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Content");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    write_note_to_flash(chsn_slot, entered_title, input_from_the_ps2_keyboard);
  }
  return;
}

void add_note_from_serial(int chsn_slot) {
  get_title_for_note_from_serial(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void get_title_for_note_from_serial(int chsn_slot) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Title");
    Serial.println("\nPaste the title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    get_content_for_note_from_serial(chsn_slot, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_content_for_note_from_serial(int chsn_slot, String entered_title) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Content");
    Serial.println("\nPaste the content here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    write_note_to_flash(chsn_slot, entered_title, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void write_note_to_flash(int chsn_slot, String entered_title, String entered_content) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Adding Note");
  tft.setCursor(0, 10);
  tft.print("To The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_content);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_cnt", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_content);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_note_and_tag(int chsn_slot, String new_content) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing Note");
  tft.setCursor(0, 10);
  tft.print("In The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_content);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_cnt", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;

  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + new_content);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/N" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_note_from_keyboard_and_encdr(int chsn_slot) {
  if (read_file("/N" + String(chsn_slot) + "_cnt") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_cnt"));
    String old_password = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Note");
    input_from_the_ps2_keyboard = old_password;
    disp();
    ps2_input_from_the_ps2_keyboard();
    if (act == true) {
      update_note_and_tag(chsn_slot, input_from_the_ps2_keyboard);
    }
  }
  return;
}

void edit_note_from_serial(int chsn_slot) {
  if (read_file("/N" + String(chsn_slot) + "_cnt") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
    press_any_key_to_continue();
  } else {
    bool cont_to_next = false;
    while (cont_to_next == false) {
      disp_paste_smth_inscr("New Content");
      Serial.println("\nPaste new content here:");
      bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
      if (canc_op == true)
        break;
      update_note_and_tag(chsn_slot, Serial.readString());
      cont_to_next = true;
      break;
    }
  }
  return;
}

void delete_note(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting Note");
  tft.setCursor(0, 10);
  tft.print("From The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  delete_file("/N" + String(chsn_slot) + "_tag");
  delete_file("/N" + String(chsn_slot) + "_ttl");
  delete_file("/N" + String(chsn_slot) + "_cnt");
  clear_variables();
  call_main_menu();
  return;
}

void view_note(int chsn_slot) {
  if (read_file("/N" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_cnt"));
    String decrypted_content = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/N" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_content;
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Content:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_content);
      tft.setTextSize(1);
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, current_inact_clr);
      disp_centered_text(succs_ver_inscr, 120);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Content:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_content);
      tft.setTextSize(1);
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, five_six_five_red_color);
      disp_centered_text(faild_ver_inscr, 120);
    }
    act = false;
    up_or_encdr_bttn_to_print();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Content:\"");
      Serial.print(decrypted_content);
      Serial.println("\"");
      if (login_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

// Functions for Notes (Above)

// Functions for Phone Numbers (Below)

void select_phone_number(byte what_to_do_with_it) {
  // 0 - Add phone_number
  // 1 - Edit phone_number
  // 2 - Delete phone_number
  // 3 - View phone_number
  delay(DELAY_FOR_SLOTS);
  curr_key = 1;
  
  header_for_select_phone_number(what_to_do_with_it);
  display_title_from_phone_number_without_integrity_verification();
  bool continue_to_next = false;
  while (continue_to_next == false) {
    byte input_data = get_inp_fr_ps_keybrd();
    if (input_data > 0) {
      

      if (input_data == 130)
        curr_key++;

      if (input_data == 129)
        curr_key--;

      if (curr_key < 1)
        curr_key = MAX_NUM_OF_RECS;

      if (curr_key > MAX_NUM_OF_RECS)
        curr_key = 1;

      if (input_data == 13) { // Enter
        int chsn_slot = curr_key;
        if (what_to_do_with_it == 0  && continue_to_next == false) { continue_to_next = true;
          byte inptsrc = input_source_for_data_in_flash();
          if (inptsrc == 1)
            add_phone_number_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            add_phone_number_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 1  && continue_to_next == false) { continue_to_next = true;
          byte inptsrc = input_source_for_data_in_flash();
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          if (inptsrc == 1)
            edit_phone_number_from_keyboard_and_encdr(chsn_slot);
          if (inptsrc == 2)
            edit_phone_number_from_serial(chsn_slot);
        }
        if (what_to_do_with_it == 2  && continue_to_next == false) { continue_to_next = true;
          delete_phone_number(chsn_slot);
        }
        if (what_to_do_with_it == 3  && continue_to_next == false) { continue_to_next = true;
          tft.fillScreen(0x0000);
          tft.setTextSize(1);
          tft.setTextColor(0xffff);
          tft.setCursor(0, 0);
          tft.print("Decrypting the record...");
          tft.setCursor(0, 10);
          tft.print("Please wait for a while.");
          view_phone_number(chsn_slot);
        }
        continue_to_next = true;
        break;
      }

      if (input_data == 27) {
        call_main_menu();
        continue_to_next = true;
        break;
      }
      delay(DELAY_FOR_SLOTS);
      header_for_select_phone_number(what_to_do_with_it);
      display_title_from_phone_number_without_integrity_verification();
    }
    delayMicroseconds(500);
  }
  return;
}

void header_for_select_phone_number(byte what_to_do_with_it) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  if (what_to_do_with_it == 0){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Phone to Slot " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 1){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Phone Number " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
  if (what_to_do_with_it == 2){
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Delete Phone " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation_for_del();
  }
  if (what_to_do_with_it == 3){
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Phone Number " + String(curr_key) + "/" + String(MAX_NUM_OF_RECS), 5);
    disp_button_designation();
  }
}

void display_title_from_phone_number_without_integrity_verification() {
  tft.setTextSize(1);
  String encrypted_title = read_file("/P" + String(curr_key) + "_ttl");
  if (encrypted_title == "-1") {
    tft.setTextColor(0x07e0);
    disp_centered_text("Empty", 20);
  } else {
    clear_variables();
    decrypt_tag = false;
    decrypt_with_TDES_AES_Blowfish_Serp(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(dec_st, 20);
  }
}

void add_phone_number_from_keyboard_and_encdr(int chsn_slot) {
  enter_title_for_phone_number(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void enter_title_for_phone_number(int chsn_slot) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Title");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    enter_phone_number_for_phone_number(chsn_slot, input_from_the_ps2_keyboard);
  }
  return;
}

void enter_phone_number_for_phone_number(int chsn_slot, String entered_title) {
  act = true;
  clear_variables();
  set_stuff_for_input("Enter Phone Number");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    write_phone_number_to_flash(chsn_slot, entered_title, input_from_the_ps2_keyboard);
  }
  return;
}

void add_phone_number_from_serial(int chsn_slot) {
  get_title_for_phone_number_from_serial(chsn_slot);
  clear_variables();
  call_main_menu();
  return;
}

void get_title_for_phone_number_from_serial(int chsn_slot) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Title");
    Serial.println("\nPaste the title here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    get_phone_number_for_phone_number_from_serial(chsn_slot, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void get_phone_number_for_phone_number_from_serial(int chsn_slot, String entered_title) {
  bool cont_to_next = false;
  while (cont_to_next == false) {
    disp_paste_smth_inscr("Phone Number");
    Serial.println("\nPaste the phone number here:");
    bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
    if (canc_op == true)
      break;
    write_phone_number_to_flash(chsn_slot, entered_title, Serial.readString());
    cont_to_next = true;
    break;
  }
  return;
}

void write_phone_number_to_flash(int chsn_slot, String entered_title, String entered_phone_number) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Adding Phone Number");
  tft.setCursor(0, 10);
  tft.print("To The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_ttl", dec_st);
  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(entered_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_cnt", dec_st);
  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(entered_title + entered_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void update_phone_number_and_tag(int chsn_slot, String new_phone_number) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Editing Phone Number");
  tft.setCursor(0, 10);
  tft.print("In The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");

  clear_variables();
  encrypt_with_TDES_AES_Blowfish_Serp(new_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_cnt", dec_st);

  clear_variables();
  decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_ttl"));
  String decrypted_title = dec_st;

  clear_variables();
  encr_hash_for_tdes_aes_blf_srp(decrypted_title + new_phone_number);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/P" + String(chsn_slot) + "_tag", dec_st);
  return;
}

void edit_phone_number_from_keyboard_and_encdr(int chsn_slot) {
  if (read_file("/P" + String(chsn_slot) + "_cnt") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_cnt"));
    String old_password = dec_st;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Phone Number");
    input_from_the_ps2_keyboard = old_password;
    disp();
    ps2_input_from_the_ps2_keyboard();
    if (act == true) {
      update_phone_number_and_tag(chsn_slot, input_from_the_ps2_keyboard);
    }
  }
  return;
}

void edit_phone_number_from_serial(int chsn_slot) {
  if (read_file("/P" + String(chsn_slot) + "_cnt") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
    press_any_key_to_continue();
  } else {
    bool cont_to_next = false;
    while (cont_to_next == false) {
      disp_paste_smth_inscr("New Phone Number");
      Serial.println("\nPaste new phone number here:");
      bool canc_op = false;
    while (!Serial.available()) {
      byte input_data = get_inp_fr_ps_keybrd();
      if (input_data > 0) {
        canc_op = true;
      }
      delayMicroseconds(400);
      if (canc_op == true)
        break;
    }
      if (canc_op == true)
        break;
      update_phone_number_and_tag(chsn_slot, Serial.readString());
      cont_to_next = true;
      break;
    }
  }
  return;
}

void delete_phone_number(int chsn_slot) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Deleting Phone Number");
  tft.setCursor(0, 10);
  tft.print("From The slot N" + String(chsn_slot) + "...");
  tft.setCursor(0, 20);
  tft.print("Please wait for a while.");
  delete_file("/P" + String(chsn_slot) + "_tag");
  delete_file("/P" + String(chsn_slot) + "_ttl");
  delete_file("/P" + String(chsn_slot) + "_cnt");
  clear_variables();
  call_main_menu();
  return;
}

void view_phone_number(int chsn_slot) {
  if (read_file("/P" + String(chsn_slot) + "_ttl") == "-1") {
    tft.fillScreen(0x0000);
    tft.setTextColor(0x07e0);
    tft.setTextSize(1);
    disp_centered_text("The Slot N" + String(chsn_slot) + " is Empty", 5);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    disp_centered_text("Press Any Key", 110);   disp_centered_text("To Cancel", 120);
    press_any_key_to_continue();
  } else {
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_ttl"));
    String decrypted_title = dec_st;
    clear_variables();
    decrypt_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_cnt"));
    String decrypted_phone_number = dec_st;
    clear_variables();
    decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/P" + String(chsn_slot) + "_tag"));
    dec_st = decrypted_title + decrypted_phone_number;
    bool login_integrity = verify_integrity();

    if (login_integrity == true) {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Phone Number:");
      tft.setTextColor(0xffff);
      tft.println(decrypted_phone_number);
      tft.setTextSize(1);
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, current_inact_clr);
      disp_centered_text(succs_ver_inscr, 120);
    } else {
      tft.fillScreen(0x0000);
      tft.setTextSize(1);
      tft.setCursor(0, 0);
      tft.setTextColor(current_inact_clr);
      tft.print("Title:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_title);
      tft.setTextColor(current_inact_clr);
      tft.print("Phone Number:");
      tft.setTextColor(five_six_five_red_color);
      tft.println(decrypted_phone_number);
      tft.setTextSize(1);
      tft.fillRect(0, 118, 160, 14, 0x0000);
      tft.fillRect(155, 0, 4, 128, five_six_five_red_color);
      disp_centered_text(faild_ver_inscr, 120);
    }
    act = false;
    up_or_encdr_bttn_to_print();
    if (act == true) {
      Serial.println();
      Serial.print("Title:\"");
      Serial.print(decrypted_title);
      Serial.println("\"");
      Serial.print("Phone Number:\"");
      Serial.print(decrypted_phone_number);
      Serial.println("\"");
      if (login_integrity == true) {
        Serial.println("Integrity Verified Successfully!\n");
      } else {
        Serial.println("Integrity Verification Failed!!!\n");
      }
    }
  }
}

// Functions for Phone Number (Above)

// Functions that work with files in Firebase (Above)

void up_or_encdr_bttn_to_print() {
  bool break_the_loop = false;
  while (break_the_loop == false) {
    byte input_data = get_inp_fr_ps_keybrd();
    if (input_data > 0) {
      
      if (input_data == 131) {
        act = true;
        break_the_loop = true;
      } else
        break_the_loop = true;
    }
    delayMicroseconds(4);
  }
}

void continue_to_unlock() {
  if (read_file("/mpass").equals("-1"))
    set_pass();
  else
    unlock_midbar();
  return;
}

void set_pass() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Set Master Password");
  ps2_input_from_the_ps2_keyboard();
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  print_centered_custom_hebrew_font("Mdbr", -8, colors, 4);
  tft.setTextColor(0xffff);
  disp_centered_text("Setting Master Password", sdown + 10);
  disp_centered_text("Please wait", sdown + 20);
  disp_centered_text("for a while", sdown + 30);
  //Serial.println(input_from_the_ps2_keyboard);
  String bck = input_from_the_ps2_keyboard;
  modify_keys();
  input_from_the_ps2_keyboard = bck;
  set_psswd();
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  print_centered_custom_hebrew_font("Mdbr", -8, colors, 4);
  tft.setTextColor(0xffff);
  disp_centered_text("Master Password Set", sdown + 10);
  disp_centered_text("Successfully", sdown + 20);
  disp_centered_text("Press Any Key", 110);
  disp_centered_text("To Continue", 120);
  press_any_key_to_continue();
  call_main_menu();
  return;
}

void set_psswd() {
  int str_len = input_from_the_ps2_keyboard.length() + 1;
  char input_arr[str_len];
  input_from_the_ps2_keyboard.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr * 2; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
    delay(1);
    if (i == ((numofkincr * 2) / 3)) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j], HEX);
      }
    }
    if (i == numofkincr) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j + 8], HEX);
      }
    }
    if (i == ((numofkincr * 3) / 2)) {
      for (int j = 0; j < 16; j++) {
        h += String(read_cards[j], HEX);
      }
    }
  }
  //Serial.println();
  //Serial.println(h);
  back_keys();
  dec_st = "";
  encr_hash_for_tdes_aes_blf_srp(h);
  rest_keys();
  //Serial.println(dec_st);

  write_to_file_with_overwrite("/mpass", dec_st);
}

void modify_keys() {
  input_from_the_ps2_keyboard += kderalgs;
  int str_len = input_from_the_ps2_keyboard.length() + 1;
  char input_arr[str_len];
  input_from_the_ps2_keyboard.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
    delay(1);
    if (i == numofkincr / 2) {
      for (int j = 0; j < 16; j++) {
        h += String(read_cards[j], HEX);
      }
    }
  }
  //Serial.println(h);
  int h_len = h.length() + 1;
  char h_array[h_len];
  h.toCharArray(h_array, h_len);
  byte res[64];
  for (int i = 0; i < 128; i += 2) {
    if (i == 0) {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i] = 0;
    } else {
      if (h_array[i] != 0 && h_array[i + 1] != 0)
        res[i / 2] = 16 * getNum(h_array[i]) + getNum(h_array[i + 1]);
      if (h_array[i] != 0 && h_array[i + 1] == 0)
        res[i / 2] = 16 * getNum(h_array[i]);
      if (h_array[i] == 0 && h_array[i + 1] != 0)
        res[i / 2] = getNum(h_array[i + 1]);
      if (h_array[i] == 0 && h_array[i + 1] == 0)
        res[i / 2] = 0;
    }
  }
  for (int i = 0; i < 13; i++) {
    hmackey[i] = res[i];
  }
  des_key[9] = res[13];
  des_key[16] = (unsigned char) res[31];
  des_key[17] = (unsigned char) res[32];
  des_key[18] = (unsigned char) res[33];
  serp_key[12] = int(res[34]);
  serp_key[14] = int(res[35]);
  for (int i = 0; i < 9; i++) {
    Blwfsh_key[i] = (unsigned char) res[i + 14];
  }
  for (int i = 0; i < 3; i++) {
    des_key[i] = (unsigned char) res[i + 23];
  }
  for (int i = 0; i < 5; i++) {
    hmackey[i + 13] = int(res[i + 26]);
  }
  for (int i = 0; i < 10; i++) {
    AES_key[i] = int(res[i + 36]);
  }
  for (int i = 0; i < 9; i++) {
    serp_key[i] = int(res[i + 46]);
  }
  for (int i = 0; i < 4; i++) {
    hmackey[i + 18] = res[i + 55];
    des_key[i + 3] = (unsigned char) res[i + 59];
  }
  for (int i = 0; i < 5; i++) {
    second_AES_key[i] = ((int(res[i + 31]) * int(res[i + 11])) + int(res[50])) % 256;
  }
}

void unlock_midbar() {
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Enter Master Password");
  starred_ps2_input_from_the_ps2_keyboard();
  tft.fillScreen(0x0000);
  print_centered_custom_hebrew_font("Mdbr", -8, colors, 4);
  tft.setTextSize(1);
  disp_centered_text("Unlocking Midbar", sdown + 10);
  disp_centered_text("Please wait", sdown + 20);
  disp_centered_text("for a while", sdown + 30);
  //Serial.println(input_from_the_ps2_keyboard);
  String bck = input_from_the_ps2_keyboard;
  modify_keys();
  input_from_the_ps2_keyboard = bck;
  bool next_act = hash_psswd();
  clear_variables();
  tft.fillScreen(0x0000);
  if (next_act == true) {
    tft.setTextSize(1);
    print_centered_custom_hebrew_font("Mdbr", -8, colors, 4);
    disp_centered_text("Midbar unlocked", sdown + 10);
    disp_centered_text("successfully", sdown + 20);
    disp_centered_text("Press Any Key", 110);
    disp_centered_text("To Continue", 120);
    press_any_key_to_continue();
    call_main_menu();
    return;
  } else {
    tft.setTextSize(1);
    print_centered_custom_hebrew_font("Mdbr", -8, colors, 4);
    tft.setTextColor(five_six_five_red_color);
    disp_centered_text("Wrong Password!", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Please reboot", sdown + 30);
    disp_centered_text("the device", sdown + 40);
    disp_centered_text("and try again", sdown + 50);
    for (;;)
      delay(1000);
  }
}

bool hash_psswd() {
  int str_len = input_from_the_ps2_keyboard.length() + 1;
  char input_arr[str_len];
  input_from_the_ps2_keyboard.toCharArray(input_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += input_arr[i];
    }
  }
  String h = sha512(str).c_str();
  for (int i = 0; i < numofkincr * 2; i++) {
    int str_len1 = h.length() + 1;
    char input_arr1[str_len1];
    h.toCharArray(input_arr1, str_len1);
    std::string str1 = "";
    if (str_len1 > 1) {
      for (int i = 0; i < str_len1 - 1; i++) {
        str1 += input_arr1[i];
      }
    }
    h = sha512(str1).c_str();
    delay(1);
    if (i == ((numofkincr * 2) / 3)) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j], HEX);
      }
    }
    if (i == numofkincr) {
      for (int j = 0; j < 8; j++) {
        h += String(read_cards[j + 8], HEX);
      }
    }
    if (i == ((numofkincr * 3) / 2)) {
      for (int j = 0; j < 16; j++) {
        h += String(read_cards[j], HEX);
      }
    }
  }
  //Serial.println();
  //Serial.println(h);

  SHA256HMAC hmac(hmackey, sizeof(hmackey));
  int h_len1 = h.length() + 1;
  char h_arr[h_len1];
  h.toCharArray(h_arr, h_len1);
  hmac.doUpdate(h_arr);
  byte authCode[SHA256HMAC_SIZE];
  hmac.doFinal(authCode);
  int p = 0;
  char hmacchar[30];
  for (int i = 0; i < 30; i++) {
    hmacchar[i] = char(authCode[i]);
  }

  String res_hash;
  for (int i = 0; i < 30; i++) {
    if (hmacchar[i] < 0x10)
      res_hash += "0";
    res_hash += String(hmacchar[i], HEX);
  }
  /*
    Serial.println();

      for (int i = 0; i < 30; i++) {
        if (hmacchar[i] < 16)
          Serial.print("0");
        Serial.print(hmacchar[i], HEX);
      }
    Serial.println();
  */
  back_keys();
  clear_variables();
  //Serial.println(read_file("/mpass"));
  decrypt_tag_with_TDES_AES_Blowfish_Serp(read_file("/mpass"));
  //Serial.println(dec_tag);
  return dec_tag.equals(res_hash);
}

int get_offset(String text_to_print){
  int shift_right = 160;
  for (int s = 0; s < text_to_print.length(); s++){ // Traverse the string

    if (text_to_print.charAt(s) == 'b'){ // Bet
      shift_right -= sizeof(Bet)/sizeof(Bet[0]);
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'd'){ // Dalet
      shift_right -= sizeof(Dalet)/sizeof(Dalet[0]);
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'M'){ // Mem
      shift_right -= sizeof(Mem)/sizeof(Mem[0]);
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'r'){ // Resh
      shift_right -= sizeof(Resh)/sizeof(Resh[0]);
      shift_right -= letter_spacing_pxls;
    }

  }
  shift_right += letter_spacing_pxls;
  return shift_right / 2;
}

void print_centered_custom_hebrew_font(String text_to_print, int y, uint16_t font_colors[], int how_many_colors){
  print_custom_multi_colored_hebrew_font(text_to_print, y, get_offset(text_to_print), font_colors, how_many_colors);
}

void print_custom_multi_colored_hebrew_font(String text_to_print, int y, int offset_from_the_right, uint16_t font_colors[], int how_many_colors){
  int shift_right = 160 - offset_from_the_right;
  for (int s = 0; s < text_to_print.length(); s++){ // Traverse the string

    if (text_to_print.charAt(s) == 'b'){ // Bet
      shift_right -= sizeof(Bet)/sizeof(Bet[0]);
      for (int i = 0; i < 22; i++) {
        for (int j = 0; j < 24; j++) {
          if (Bet[i][j] == 0)
            tft.drawPixel(i + shift_right, j + y + regular_shift_down, font_colors[s % how_many_colors]);
        }
      }
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'd'){ // Dalet
      shift_right -= sizeof(Dalet)/sizeof(Dalet[0]);
      for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 24; j++) {
          if (Dalet[i][j] == 0)
            tft.drawPixel(i + shift_right, j + y + regular_shift_down, font_colors[s % how_many_colors]);
        }
      }
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'M'){ // Mem
      shift_right -= sizeof(Mem)/sizeof(Mem[0]);
      for (int i = 0; i < 18; i++) {
        for (int j = 0; j < 29; j++) {
          if (Mem[i][j] == 0)
            tft.drawPixel(i + shift_right, j + y + shift_down_for_mem, font_colors[s % how_many_colors]);
        }
      }
      shift_right -= letter_spacing_pxls;
    }

    if (text_to_print.charAt(s) == 'r'){ // Resh
      shift_right -= sizeof(Resh)/sizeof(Resh[0]);
      for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 24; j++) {
          if (Resh[i][j] == 0)
            tft.drawPixel(i + shift_right, j + y + regular_shift_down, font_colors[s % how_many_colors]);
        }
      }
      shift_right -= letter_spacing_pxls;
    }
  }
}

// Menu (below)

void disp_paste_smth_inscr(String what_to_pst) {
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  disp_centered_text("Paste", 10);
  disp_centered_text(what_to_pst, 20);
  disp_centered_text("To The Serial Terminal", 30);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Press Any Key", 110);
  disp_centered_text("To Cancel", 120);
}

void disp_button_designation() {
  tft.setTextSize(1);
  tft.setTextColor(0x07e0);
  tft.setCursor(0, 120);
  tft.print("Enter:");
  tft.print("Continue    ");
  tft.setTextColor(five_six_five_red_color);
  tft.print("Esc:");
  tft.print("Back");
}

void disp_button_designation_for_del() {
  tft.setTextSize(1);
  tft.setTextColor(five_six_five_red_color);
  tft.setCursor(0, 120);
  tft.print("Enter:");
  tft.print("Continue    ");
  tft.setTextColor(0x07e0);
  tft.print("Esc:");
  tft.print("Back");
}

void call_main_menu(){
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  print_centered_custom_hebrew_font("Mdbr", -8, colors, 4);
  curr_pos = 0;
  main_menu();
}

void main_menu() {
  tft.setTextSize(1);
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Logins", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Credit Cards", sdown + 20);
    disp_centered_text("Notes", sdown + 30);
    disp_centered_text("Phone Numbers", sdown + 40);
    disp_centered_text("Hash Functions", sdown + 50);
    disp_centered_text("Factory Reset", sdown + 60);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Credit Cards", sdown + 20);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Notes", sdown + 30);
    disp_centered_text("Phone Numbers", sdown + 40);
    disp_centered_text("Hash Functions", sdown + 50);
    disp_centered_text("Factory Reset", sdown + 60);
  }
  if (curr_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 20);
    tft.setTextColor(0xffff);
    disp_centered_text("Notes", sdown + 30);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Phone Numbers", sdown + 40);
    disp_centered_text("Hash Functions", sdown + 50);
    disp_centered_text("Factory Reset", sdown + 60);
  }
  if (curr_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 20);
    disp_centered_text("Notes", sdown + 30);
    tft.setTextColor(0xffff);
    disp_centered_text("Phone Numbers", sdown + 40);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Hash Functions", sdown + 50);
    disp_centered_text("Factory Reset", sdown + 60);
  }
  if (curr_pos == 4) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 20);
    disp_centered_text("Notes", sdown + 30);
    disp_centered_text("Phone Numbers", sdown + 40);
    tft.setTextColor(0xffff);
    disp_centered_text("Hash Functions", sdown + 50);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Factory Reset", sdown + 60);
  }
  if (curr_pos == 5) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Logins", sdown + 10);
    disp_centered_text("Credit Cards", sdown + 20);
    disp_centered_text("Notes", sdown + 30);
    disp_centered_text("Phone Numbers", sdown + 40);
    disp_centered_text("Hash Functions", sdown + 50);
    tft.setTextColor(0xffff);
    disp_centered_text("Factory Reset", sdown + 60);
  }
}

void input_source_for_data_in_flash_menu(int curr_pos) {
  tft.setTextSize(1);
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("PS/2 Keyboard", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("PS/2 Keyboard", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Serial Terminal", sdown + 20);
  }
}

byte input_source_for_data_in_flash() {
  byte inpsrc = 0;
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Choose Input Source", 10);
  curr_key = 0;
  input_source_for_data_in_flash_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    byte input_data = get_inp_fr_ps_keybrd();
    if (input_data > 0) {
      

      if (input_data == 131 || input_data == 129)
        curr_key--;

      if (input_data == 132 || input_data == 130)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (input_data == 13) {
        if (curr_key == 0) {
          inpsrc = 1;
        }

        if (curr_key == 1  && cont_to_next == false) {
          inpsrc = 2;
        }
        cont_to_next = true;
        break;
      }
      if (input_data == 27) {
        cont_to_next = true;
        break;
      }
      input_source_for_data_in_flash_menu(curr_key);

    }
  }
  return inpsrc;
}

void action_for_data_in_flash_menu(int curr_pos) {
  tft.setTextSize(1);
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("Add", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit", sdown + 20);
    disp_centered_text("Delete", sdown + 30);
    disp_centered_text("View", sdown + 40);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("Edit", sdown + 20);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Delete", sdown + 30);
    disp_centered_text("View", sdown + 40);
  }
  if (curr_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 20);
    tft.setTextColor(0xffff);
    disp_centered_text("Delete", sdown + 30);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View", sdown + 40);
  }
  if (curr_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add", sdown + 10);
    disp_centered_text("Edit", sdown + 20);
    disp_centered_text("Delete", sdown + 30);
    tft.setTextColor(0xffff);
    disp_centered_text("View", sdown + 40);
  }
}

void action_for_data_in_flash(String menu_title, byte record_type) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  disp_centered_text(menu_title, 10);
  curr_key = 0;
  
  action_for_data_in_flash_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    byte input_data = get_inp_fr_ps_keybrd();
    if (input_data > 0) {
      

      if (input_data == 131 || input_data == 129)
        curr_key--;

      if (input_data == 132 || input_data == 130)
        curr_key++;

      if (curr_key < 0)
        curr_key = 3;

      if (curr_key > 3)
        curr_key = 0;

      if (input_data == 13) {
        if (curr_key == 0) {
          if (record_type == 0)
            select_login(0);
          if (record_type == 1)
            select_credit_card(0);
          if (record_type == 2)
            select_note(0);
          if (record_type == 3)
            select_phone_number(0);
          cont_to_next = true;
        }

        if (curr_key == 1  && cont_to_next == false) {
          if (record_type == 0)
            select_login(1);
          if (record_type == 1)
            select_credit_card(1);
          if (record_type == 2)
            select_note(1);
          if (record_type == 3)
            select_phone_number(1);
          cont_to_next = true;
        }

        if (curr_key == 2  && cont_to_next == false) {
          if (record_type == 0)
            select_login(2);
          if (record_type == 1)
            select_credit_card(2);
          if (record_type == 2)
            select_note(2);
          if (record_type == 3)
            select_phone_number(2);
          cont_to_next = true;
        }

        if (curr_key == 3  && cont_to_next == false) {
          if (record_type == 0)
            select_login(3);
          if (record_type == 1)
            select_credit_card(3);
          if (record_type == 2)
            select_note(3);
          if (record_type == 3)
            select_phone_number(3);
          cont_to_next = true;
        }
      }
      if (input_data == 27) {
        cont_to_next = true;
      }
      action_for_data_in_flash_menu(curr_key);

    }
  }
  call_main_menu();
}

void hash_functions_menu(int curr_pos) {
  tft.setTextSize(1);
  if (curr_pos == 0) {
    tft.setTextColor(0xffff);
    disp_centered_text("SHA-256", sdown + 10);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("SHA-512", sdown + 20);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("SHA-256", sdown + 10);
    tft.setTextColor(0xffff);
    disp_centered_text("SHA-512", sdown + 20);
  }
}

void hash_functions() {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  disp_centered_text("Hash Functions", 10);
  curr_key = 0;
  hash_functions_menu(curr_key);
  disp_button_designation();
  bool cont_to_next = false;
  while (cont_to_next == false) {
    byte input_data = get_inp_fr_ps_keybrd();
    if (input_data > 0) {
      if (input_data == 131 || input_data == 129)
        curr_key--;

      if (input_data == 132 || input_data == 130)
        curr_key++;

      if (curr_key < 0)
        curr_key = 1;

      if (curr_key > 1)
        curr_key = 0;

      if (input_data == 13) {
        if (curr_key == 0) {
          hash_string_with_sha(false);
          cont_to_next = true;
        }

        if (curr_key == 1  && cont_to_next == false) {
          hash_string_with_sha(true);
          cont_to_next = true;
        }
      }
      if (input_data == 27) {
        cont_to_next = true;
      }
      hash_functions_menu(curr_key);

    }
  }
  call_main_menu();
}

// Menu (Above)

void Factory_Reset() {
  tft.fillScreen(0x0000);
  tft.setTextColor(five_six_five_red_color);
  disp_centered_text("Factory Reset", 0);
  delay(500);
  disp_centered_text("Attention!!!", 20);
  tft.setTextColor(0xffff);
  delay(500);
  disp_centered_text("All your data", 40);
  delay(500);
  disp_centered_text("will be lost!", 50);
  delay(500);
  tft.setTextColor(0x1557);
  disp_centered_text("Are you sure you want", 80);
  disp_centered_text("to continue?", 90);
  tft.setTextSize(1);
  delay(5000);
  
  disp_button_designation_for_del();
  finish_input = false;
  while (finish_input == false) {
    byte input_data = get_inp_fr_ps_keybrd();
      if (input_data == 13) {
        perform_factory_reset();
        finish_input = true;
      }

      if (input_data == 27) {
        finish_input = true;
      }
    delayMicroseconds(4);
  }
  clear_variables();
  call_main_menu();
  return;
}

void perform_factory_reset() {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.print("Performing Factory Reset...");
  tft.setCursor(0, 10);
  tft.print("Please wait for a while.");
  delay(1000);
  delete_file("/mpass");
  for (int i = 0; i < MAX_NUM_OF_RECS; i++) {
    delete_file("/L" + String(i + 1) + "_tag");
    delete_file("/L" + String(i + 1) + "_ttl");
    delete_file("/L" + String(i + 1) + "_usn");
    delete_file("/L" + String(i + 1) + "_psw");
    delete_file("/L" + String(i + 1) + "_wbs");
    delete_file("/C" + String(i + 1) + "_tag");
    delete_file("/C" + String(i + 1) + "_ttl");
    delete_file("/C" + String(i + 1) + "_hld");
    delete_file("/C" + String(i + 1) + "_nmr");
    delete_file("/C" + String(i + 1) + "_exp");
    delete_file("/C" + String(i + 1) + "_cvn");
    delete_file("/C" + String(i + 1) + "_pin");
    delete_file("/C" + String(i + 1) + "_zip");
    delete_file("/N" + String(i + 1) + "_tag");
    delete_file("/N" + String(i + 1) + "_ttl");
    delete_file("/N" + String(i + 1) + "_cnt");
    delete_file("/P" + String(i + 1) + "_tag");
    delete_file("/P" + String(i + 1) + "_ttl");
    delete_file("/P" + String(i + 1) + "_cnt");
    tft.fillScreen(0x0000);
    tft.setTextSize(1);
    tft.setTextColor(0xffff);
    tft.setCursor(0, 0);
    tft.print("Performing Factory Reset...");
    tft.setCursor(0, 10);
    tft.print("Progress " + String((float(i + 1) / float(MAX_NUM_OF_RECS)) * 100) + "%");
  }
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  disp_centered_text("DONE!", 10);
  disp_centered_text("Please Reboot", 30);
  disp_centered_text("The Device", 40);
  delay(1000);
  for (;;) {}
}

void hash_string_with_sha(bool vrsn) {
  act = true;
  clear_variables();
  tft.fillScreen(0x0000);
  tft.setTextColor(0xffff);
  tft.setTextSize(1);
  set_stuff_for_input("Enter string to hash:");
  ps2_input_from_the_ps2_keyboard();
  if (act == true) {
    if (vrsn == false)
      hash_with_sha256();
    else
      hash_with_sha512();
  }
  clear_variables();
  curr_key = 0;
  call_main_menu();
  return;
}

void hash_with_sha256() {
  int str_len = input_from_the_ps2_keyboard.length() + 1;
  char keyb_inp_arr[str_len];
  input_from_the_ps2_keyboard.toCharArray(keyb_inp_arr, str_len);
  SHA256 hasher;
  hasher.doUpdate(keyb_inp_arr, strlen(keyb_inp_arr));
  byte authCode[SHA256_SIZE];
  hasher.doFinal(authCode);

  String res_hash;
  for (byte i = 0; i < SHA256HMAC_SIZE; i++) {
    if (authCode[i] < 0x10) {
      res_hash += 0;
    } {
      res_hash += String(authCode[i], HEX);
    }
  }
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(1);
  disp_centered_text("Resulted hash", 10);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.println(res_hash);
  press_any_key_to_continue();
}

void hash_with_sha512() {
  int str_len = input_from_the_ps2_keyboard.length() + 1;
  char keyb_inp_arr[str_len];
  input_from_the_ps2_keyboard.toCharArray(keyb_inp_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += keyb_inp_arr[i];
    }
  }
  String h = sha512(str).c_str();
  tft.fillScreen(0x0000);
  tft.setTextColor(current_inact_clr);
  tft.setTextSize(1);
  disp_centered_text("Resulted hash", 10);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 20);
  tft.println(h);
  press_any_key_to_continue();
}

void Wifi_Init() {
  tft.setTextSize(1);
  tft.setTextColor(0xffff);
  tft.setCursor(0, 0);
  tft.println("Connecting to Wi-Fi");
  tft.setCursor(0, 12);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  while (WiFi.status() != WL_CONNECTED) {
    delay(300);
    tft.print("#");
  }
}

void firebase_init() {
  tft.fillScreen(0x0000);
  print_centered_custom_hebrew_font("Mdbr", 0, colors, 4);
  disp_centered_text("Initializing Firebase", 120);
  // configure firebase API Key
  config.api_key = API_KEY;
  // configure firebase realtime database url
  config.database_url = DATABASE_URL;
  // Enable WiFi reconnection 
  Firebase.reconnectWiFi(true);
  if (Firebase.signUp( & config, & auth, "", "")) {
    isAuthenticated = true;
    fuid = auth.token.uid.c_str();
  } else {
    delay(40);
    isAuthenticated = false;
    tft.fillScreen(0x0000);
    tft.setTextColor(0xf800);
    disp_centered_text("Failed To Initialize", 5);
    disp_centered_text("FIrebase", 20);
    disp_centered_text("Please reboot", sdown + 30);
    disp_centered_text("the device", sdown + 40);
    disp_centered_text("and try again", sdown + 50);
    while(1){
      delay(1000);
    }
  }
  // Assign the callback function for the long running token generation task, see addons/TokenHelper.h
  config.token_status_callback = tokenStatusCallback;
  // Initialise the firebase library
  Firebase.begin( & config, & auth);
}

void display_lck_scrn(byte scr_nr){
  if (scr_nr == 0){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Atlanta[i][j]);
      }
    }
  }
  
  if (scr_nr == 1){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Beer_Sheva[i][j]);
      }
    }
  }
  
  if (scr_nr == 2){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Dallas[i][j]);
      }
    }
  }

  if (scr_nr == 3){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Dallas_1[i][j]);
      }
    }
  }

  if (scr_nr == 4){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Frankfurt[i][j]);
      }
    }
  }

  if (scr_nr == 5){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Kansas_City[i][j]);
      }
    }
  }

  if (scr_nr == 6){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Los_Angeles[i][j]);
      }
    }
  }

  if (scr_nr == 7){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Minneapolis[i][j]);
      }
    }
  }

  if (scr_nr == 8){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Nashville[i][j]);
      }
    }
  }

  if (scr_nr == 9){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Netanya[i][j]);
      }
    }
  }

  if (scr_nr == 10){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, New_Orleans[i][j]);
      }
    }
  }

  if (scr_nr == 11){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Pittsburgh[i][j]);
      }
    }
  }

  if (scr_nr == 12){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Salt_Lake_City[i][j]);
      }
    }
  }

  if (scr_nr == 13){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Santiago[i][j]);
      }
    }
  }

  if (scr_nr == 14){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Tel_Aviv[i][j]);
      }
    }
  }

  if (scr_nr == 15){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Tel_Aviv_1[i][j]);
      }
    }
  }

  if (scr_nr == 16){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Tel_Aviv_2[i][j]);
      }
    }
  }

  if (scr_nr == 17){
    for (int i = 0; i < 160; i++) {
      for (int j = 0; j < 128; j++) {
        tft.drawPixel(i, j, Toronto[i][j]);
      }
    }
  }
  
  tft.setTextSize(1);
  tft.setTextColor(0xf7de);
  disp_centered_text_b_w("Press Any Key", 119);
}

void setup(void) {
  rec_d = false;
  tft.initR(INITR_BLACKTAB);
  tft.setRotation(1);
  tft.fillScreen(0x0000);
  Serial.begin(115200);
  Wifi_Init();
  firebase_init();
  keyboard.begin( DATAPIN, IRQPIN );
  keyboard.setNoBreak(1);
  keyboard.setNoRepeat(1);
  keymap.selectMap( (char *)"US" );
  tft.fillScreen(0x0000);
  m = 2; // Set AES to 256-bit mode
  clb_m = 4;
  display_lck_scrn(esp_random() % 18);
  press_any_key_to_continue();
  continue_to_unlock();
}

void loop() {
  byte input_data = get_inp_fr_ps_keybrd();

  if (input_data == 13){ //Enter
    if (curr_pos == 0){
      action_for_data_in_flash("Logins Menu", curr_pos);
    }
    if (curr_pos == 1){
      action_for_data_in_flash("Credit Cards Menu", curr_pos);
    }
    if (curr_pos == 2){
      action_for_data_in_flash("Notes Menu", curr_pos);
    }
    if (curr_pos == 3){
      action_for_data_in_flash("Phone Numbers Menu", curr_pos);
    }
    if (curr_pos == 4){
      hash_functions();
    }
    if (curr_pos == 5){
      Factory_Reset();
    }
  }

  if (input_data == 132 || input_data == 130){
    curr_pos++;
    if (curr_pos > 5)
      curr_pos = 0;
    main_menu();
  }

  if (input_data == 131 || input_data == 129){
    curr_pos--;
    if (curr_pos < 0)
      curr_pos = 5;
     main_menu();
  }
}

byte get_inp_fr_ps_keybrd() {
  byte data_from_cntrl_and_keyb;
  while (rec_d == false) {
    delay(4);
    get_key_from_ps_keyb();
  }
  if (rec_d == true) {
    data_from_cntrl_and_keyb = data_from_keyboard;
    rec_d = false;
  }
  return data_from_cntrl_and_keyb;
}
