/*
Midbar Firebase Edition
Distributed under the MIT License
© Copyright Maxim Bortnikov 2024
For more information please visit
https://sourceforge.net/projects/midbar-firebase-edition/
https://github.com/Northstrix/Midbar-Firebase-Edition
Required libraries:
https://github.com/zhouyangchao/AES
https://github.com/ulwanski/sha512
https://github.com/adafruit/Adafruit-ST7735-Library
https://github.com/adafruit/Adafruit-GFX-Library
https://github.com/adafruit/Adafruit_BusIO
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/mobizt/Firebase-ESP32
Credit:
https://www.pexels.com/photo/gray-and-black-hive-printed-textile-691710/
https://github.com/nishantprj/custom_tkinter_login
https://codepen.io/argyleink/pen/abXvVME
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
#include "aes.h"
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

FirebaseData fbdo;
FirebaseAuth auth;
FirebaseConfig config;
PS2KeyAdvanced keyboard;
PS2KeyMap keymap;

int m;
int clb_m;
String string_for_data;
String decrypted_hash;
byte tmp_st[8];
int pass_to_serp[16];
int decract;
byte array_for_CBC_mode[16];
String input_from_the_ps2_keyboard;
byte sdown = 36;
uint16_t code;
int curr_key;
int curr_pos;
int prsd_key;
bool finish_input;
bool act;
bool decrypt_hash;
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

uint8_t back_aes_key[32]; 
uint32_t aes_mode[3] = {128, 192, 256};
uint8_t aes_key[32];

void back_aes_k() {
  for (int i = 0; i < 32; i++) {
    back_aes_key[i] = aes_key[i];
  }
}

void rest_aes_k() {
  for (int i = 0; i < 32; i++) {
    aes_key[i] = back_aes_key[i];
  }
}

void incr_aes_key() {
  if (aes_key[15] == 255) {
    aes_key[15] = 0;
    if (aes_key[14] == 255) {
      aes_key[14] = 0;
      if (aes_key[13] == 255) {
        aes_key[13] = 0;
        if (aes_key[12] == 255) {
          aes_key[12] = 0;
          if (aes_key[11] == 255) {
            aes_key[11] = 0;
            if (aes_key[10] == 255) {
              aes_key[10] = 0;
              if (aes_key[9] == 255) {
                aes_key[9] = 0;
                if (aes_key[8] == 255) {
                  aes_key[8] = 0;
                  if (aes_key[7] == 255) {
                    aes_key[7] = 0;
                    if (aes_key[6] == 255) {
                      aes_key[6] = 0;
                      if (aes_key[5] == 255) {
                        aes_key[5] = 0;
                        if (aes_key[4] == 255) {
                          aes_key[4] = 0;
                          if (aes_key[3] == 255) {
                            aes_key[3] = 0;
                            if (aes_key[2] == 255) {
                              aes_key[2] = 0;
                              if (aes_key[1] == 255) {
                                aes_key[1] = 0;
                                if (aes_key[0] == 255) {
                                  aes_key[0] = 0;
                                } else {
                                  aes_key[0]++;
                                }
                              } else {
                                aes_key[1]++;
                              }
                            } else {
                              aes_key[2]++;
                            }
                          } else {
                            aes_key[3]++;
                          }
                        } else {
                          aes_key[4]++;
                        }
                      } else {
                        aes_key[5]++;
                      }
                    } else {
                      aes_key[6]++;
                    }
                  } else {
                    aes_key[7]++;
                  }
                } else {
                  aes_key[8]++;
                }
              } else {
                aes_key[9]++;
              }
            } else {
              aes_key[10]++;
            }
          } else {
            aes_key[11]++;
          }
        } else {
          aes_key[12]++;
        }
      } else {
        aes_key[13]++;
      }
    } else {
      aes_key[14]++;
    }
  } else {
    aes_key[15]++;
  }
}

int generate_random_number() {
  return esp_random() % 256;
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

void back_key() {
  back_aes_k();
}

void rest_key() {
  rest_aes_k();
}

void clear_variables() {
  input_from_the_ps2_keyboard = "";
  string_for_data = "";
  decrypted_hash = "";
  decract = 0;
  return;
}

// AES in CBC Mode(Below)

void split_by_sixteen_for_encryption(char plntxt[], int k, int str_len) {
  int res[] = {
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
    if (i + k > str_len - 1)
      break;
    res[i] = plntxt[i + k];
  }

  for (int i = 0; i < 16; i++) {
    res[i] ^= array_for_CBC_mode[i];
  }
  
  encrypt_with_aes(res);
}

void encrypt_iv_for_aes() {
  int iv[16]; // Initialization vector
  for (int i = 0; i < 16; i++){
    iv[i] = random(256);
  }
  for (int i = 0; i < 16; i++){
    array_for_CBC_mode[i] = iv[i];
  }
  encrypt_with_aes(iv);
}

void encrypt_with_aes(int to_be_encr[]) {
  uint8_t text[16];
  for(int i = 0; i < 16; i++){
    text[i] = to_be_encr[i];
  }
  uint8_t cipher_text[16];
  int i = 0;
  aes_context ctx;
  set_aes_key(&ctx, aes_key, aes_mode[m]);
  aes_encrypt_block(&ctx, cipher_text, text);
    incr_aes_key();
    /*
    for (int i = 0; i < 16; i++) {
      if (cipher_text[i] < 16)
        Serial.print("0");
      Serial.print(cipher_text[i], HEX);
    }
    */
    for (int i = 0; i < 16; i++) {
     if (decract > 0){
        if (i < 16){
          array_for_CBC_mode[i] = int(cipher_text[i]);
        }  
     }
     if (cipher_text[i] < 16)
        string_for_data += "0";
      string_for_data += String(cipher_text[i], HEX);
    }
    decract++;
}

void split_for_decr(char ct[], int ct_len, int p, int decract1) {
  int br = false;
  int res[] = {
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
    if(decract1 > 16){
      for (int i = 0; i < 16; i++){
        array_for_CBC_mode[i] = prev_res[i];
      }
    }
    uint8_t ret_text[16];
    uint8_t cipher_text[16];
    for(int i = 0; i<16; i++){
      cipher_text[i] = res[i];
    }
    int i = 0;
    aes_context ctx;
    set_aes_key(&ctx, aes_key, aes_mode[m]);
    aes_decrypt_block(&ctx, ret_text, cipher_text);
    incr_aes_key();
    if (decract1 > 2) {
      for (int i = 0; i < 16; i++){
        ret_text[i] ^= array_for_CBC_mode[i];
      }
      if (decrypt_hash == true){
        for (int j = 0; j < 16; j++) {
          delay(1);
          if (ret_text[j] < 16)
            decrypted_hash += "0";
          decrypted_hash += String(ret_text[j], HEX);
        }
      }
      if (decrypt_hash == false){
        for (int j = 0; j < 16; j++) {
          if (ret_text[j] > 0){
            string_for_data += char(ret_text[j]);
          }
        }
      }
    }

    if (decract1 == -1){
      for (i = 0; i < 16; ++i) {
        array_for_CBC_mode[i] = int(ret_text[i]);
      }
    }
  }
}

void encrypt_string_with_aes_in_cbc(String input) {
  back_key();
  clear_variables();
  encrypt_iv_for_aes();
  int str_len = input.length() + 1;
  char input_arr[str_len];
  input.toCharArray(input_arr, str_len);
  int p = 0;
  while (str_len > p + 1) {
    split_by_sixteen_for_encryption(input_arr, p, str_len);
    p += 16;
  }
  rest_key();
}

void decrypt_string_with_aes_in_cbc(String ct) {
  back_key();
  clear_variables();
  decrypt_hash = false;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  int decract1 = -1;
  while (ct_len > ext) {
    split_for_decr(ct_array, ct_len, 0 + ext, decract1);
    ext += 32;
    decract1 += 10;
  }
  rest_key();
}

void decrypt_hash_with_aes_in_cbc(String ct) {
  back_key();
  clear_variables();
  decrypt_hash = true;
  int ct_len = ct.length() + 1;
  char ct_array[ct_len];
  ct.toCharArray(ct_array, ct_len);
  int ext = 0;
  int decract1 = -1;
  while (ct_len > ext) {
    split_for_decr(ct_array, ct_len, 0 + ext, decract1);
    ext += 32;
    decract1 += 10;
  }
  rest_key();
}

void encrypt_hash_with_aes_in_cbc(String input) {
  back_key();
  clear_variables();
  encrypt_iv_for_aes();
  int str_len = input.length() + 1;
  char keyb_inp_arr[str_len];
  input.toCharArray(keyb_inp_arr, str_len);
  std::string str = "";
  for (int i = 0; i < str_len - 1; i++) {
    str += keyb_inp_arr[i];
  }
  String h = sha512(str).c_str();
  //Serial.println();
  //Serial.println(h);
  byte res[64];
  for (int i = 0; i < 128; i += 2) {
    if (i == 0) {
      if (h.charAt(i) != 0 && h.charAt(i + 1) != 0)
        res[i] = 16 * getNum(h.charAt(i)) + getNum(h.charAt(i + 1));
      if (h.charAt(i) != 0 && h.charAt(i + 1) == 0)
        res[i] = 16 * getNum(h.charAt(i));
      if (h.charAt(i) == 0 && h.charAt(i + 1) != 0)
        res[i] = getNum(h.charAt(i + 1));
      if (h.charAt(i) == 0 && h.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (h.charAt(i) != 0 && h.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(h.charAt(i)) + getNum(h.charAt(i + 1));
      if (h.charAt(i) != 0 && h.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(h.charAt(i));
      if (h.charAt(i) == 0 && h.charAt(i + 1) != 0)
        res[i / 2] = getNum(h.charAt(i + 1));
      if (h.charAt(i) == 0 && h.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }

  char arr_to_hash[64];
  for (int i = 0; i < 64; i++)
    arr_to_hash[i] = char(res[i]);

  int p = 0;
  for (int i = 0; i < 4; i++) {
    split_by_sixteen_for_encryption(arr_to_hash, p, 1000);
    p += 16;
  }
  rest_key();
}

// AES in CBC Mode (Above)

bool verify_integrity() {
  int str_len = string_for_data.length() + 1;
  char keyb_inp_arr[str_len];
  string_for_data.toCharArray(keyb_inp_arr, str_len);
  std::string str = "";
  for (int i = 0; i < str_len - 1; i++) {
    str += string_for_data[i];
  }
  String h = sha512(str).c_str();
  //Serial.println();
  //Serial.println(h);
  //Serial.println(decrypted_hash);
  return decrypted_hash.equals(h);
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
    decrypt_hash = false;
    decrypt_string_with_aes_in_cbc(encrypted_title);
    tft.setTextColor(0xffff);
    disp_centered_text(string_for_data, 20);
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
  encrypt_string_with_aes_in_cbc(entered_title);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_ttl", string_for_data);
  clear_variables();
  encrypt_string_with_aes_in_cbc(entered_username);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_usn", string_for_data);
  clear_variables();
  encrypt_string_with_aes_in_cbc(entered_password);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_psw", string_for_data);
  clear_variables();
  encrypt_string_with_aes_in_cbc(entered_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_wbs", string_for_data);
  clear_variables();
  encrypt_hash_with_aes_in_cbc(entered_title + entered_username + entered_password + entered_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_hash", string_for_data);
  return;
}

void update_login_and_hash(int chsn_slot, String new_password) {
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
  encrypt_string_with_aes_in_cbc(new_password);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_psw", string_for_data);

  clear_variables();
  decrypt_string_with_aes_in_cbc(read_file("/L" + String(chsn_slot) + "_ttl"));
  String decrypted_title = string_for_data;
  clear_variables();
  decrypt_string_with_aes_in_cbc(read_file("/L" + String(chsn_slot) + "_usn"));
  String decrypted_username = string_for_data;
  clear_variables();
  decrypt_string_with_aes_in_cbc(read_file("/L" + String(chsn_slot) + "_wbs"));
  String decrypted_website = string_for_data;

  clear_variables();
  encrypt_hash_with_aes_in_cbc(decrypted_title + decrypted_username + new_password + decrypted_website);
  delay(DELAY_FOR_SLOTS);
  write_to_file_with_overwrite("/L" + String(chsn_slot) + "_hash", string_for_data);
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
    decrypt_string_with_aes_in_cbc(read_file("/L" + String(chsn_slot) + "_psw"));
    String old_password = string_for_data;
    act = true;
    clear_variables();
    set_stuff_for_input("Edit Password");
    input_from_the_ps2_keyboard = old_password;
    disp();
    ps2_input_from_the_ps2_keyboard();
    if (act == true) {
      update_login_and_hash(chsn_slot, input_from_the_ps2_keyboard);
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
      update_login_and_hash(chsn_slot, Serial.readString());
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
  delete_file("/L" + String(chsn_slot) + "_hash");
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
    decrypt_string_with_aes_in_cbc(read_file("/L" + String(chsn_slot) + "_ttl"));
    String decrypted_title = string_for_data;
    clear_variables();
    decrypt_string_with_aes_in_cbc(read_file("/L" + String(chsn_slot) + "_usn"));
    String decrypted_username = string_for_data;
    clear_variables();
    decrypt_string_with_aes_in_cbc(read_file("/L" + String(chsn_slot) + "_psw"));
    String decrypted_password = string_for_data;
    clear_variables();
    decrypt_string_with_aes_in_cbc(read_file("/L" + String(chsn_slot) + "_wbs"));
    String decrypted_website = string_for_data;
    clear_variables();
    decrypt_hash_with_aes_in_cbc(read_file("/L" + String(chsn_slot) + "_hash"));
    string_for_data = decrypted_title + decrypted_username + decrypted_password + decrypted_website;
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
  //Serial.println();
  //Serial.print("Password: ");
  //Serial.println(input_from_the_ps2_keyboard);
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
  //Serial.println();
  //Serial.println(h);
  String shalf;
  for (int i = 0; i < 64; i++)
    shalf += h.charAt(i + 64);
  //Serial.println();
  //Serial.print("First Hash: ");
  //Serial.print(shalf);
  back_key();
  string_for_data = "";
  encrypt_hash_with_aes_in_cbc(shalf);
  rest_key();
  //Serial.println(string_for_data);

  write_to_file_with_overwrite("/mpass", string_for_data);
}

void modify_keys() {
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
    
  byte res[32];
  for (int i = 0; i < 64; i += 2) {
    if (i == 0) {
      if (h.charAt(i) != 0 && h.charAt(i + 1) != 0)
        res[i] = 16 * getNum(h.charAt(i)) + getNum(h.charAt(i + 1));
      if (h.charAt(i) != 0 && h.charAt(i + 1) == 0)
        res[i] = 16 * getNum(h.charAt(i));
      if (h.charAt(i) == 0 && h.charAt(i + 1) != 0)
        res[i] = getNum(h.charAt(i + 1));
      if (h.charAt(i) == 0 && h.charAt(i + 1) == 0)
        res[i] = 0;
    } else {
      if (h.charAt(i) != 0 && h.charAt(i + 1) != 0)
        res[i / 2] = 16 * getNum(h.charAt(i)) + getNum(h.charAt(i + 1));
      if (h.charAt(i) != 0 && h.charAt(i + 1) == 0)
        res[i / 2] = 16 * getNum(h.charAt(i));
      if (h.charAt(i) == 0 && h.charAt(i + 1) != 0)
        res[i / 2] = getNum(h.charAt(i + 1));
      if (h.charAt(i) == 0 && h.charAt(i + 1) == 0)
        res[i / 2] = 0;
    }
  }

  for (int i = 0; i < 32; i++) {
     aes_key[i] = (uint8_t) res[i];
  }
  /*
  for (int i = 0; i < 32; i++) {
     Serial.println(aes_key[i]);
  }
  */
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
  char keyb_inp_arr[str_len];
  input_from_the_ps2_keyboard.toCharArray(keyb_inp_arr, str_len);
  std::string str = "";
  if (str_len > 1) {
    for (int i = 0; i < str_len - 1; i++) {
      str += keyb_inp_arr[i];
    }
  }
  String h = sha512(str).c_str();
  //Serial.println();
  //Serial.print("First Hash: ");
  //Serial.println(h);

  std::string str1 = "";
  for (int i = 0; i < 64; i++) {
    str1 += h.charAt(i + 64);
  }
  String res_hash = sha512(str1).c_str();
  //Serial.println();
  //Serial.print("Second Hash: ");
  //Serial.println(res_hash);
  clear_variables();
  //Serial.println(read_file("/mpass"));
  decrypt_hash_with_aes_in_cbc(read_file("/mpass"));
  //Serial.println(decrypted_hash);
  return decrypted_hash.equals(res_hash);
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
  curr_pos = 0;
  action_for_data_in_flash("", 0);
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
    disp_centered_text("Add Login", sdown + 40);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Edit Login", sdown + 50);
    disp_centered_text("Delete Login", sdown + 60);
    disp_centered_text("View Login", sdown + 70);
  }
  if (curr_pos == 1) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Login", sdown + 40);
    tft.setTextColor(0xffff);
    disp_centered_text("Edit Login", sdown + 50);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Delete Login", sdown + 60);
    disp_centered_text("View Login", sdown + 70);
  }
  if (curr_pos == 2) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Login", sdown + 40);
    disp_centered_text("Edit Login", sdown + 50);
    tft.setTextColor(0xffff);
    disp_centered_text("Delete Login", sdown + 60);
    tft.setTextColor(current_inact_clr);
    disp_centered_text("View Login", sdown + 70);
  }
  if (curr_pos == 3) {
    tft.setTextColor(current_inact_clr);
    disp_centered_text("Add Login", sdown + 40);
    disp_centered_text("Edit Login", sdown + 50);
    disp_centered_text("Delete Login", sdown + 60);
    tft.setTextColor(0xffff);
    disp_centered_text("View Login", sdown + 70);
  }
}

void action_for_data_in_flash(String menu_title, byte record_type) {
  tft.fillScreen(0x0000);
  tft.setTextSize(1);
  tft.setTextColor(current_inact_clr);
  disp_centered_text(menu_title, 10);
  curr_key = 0;
  for (int i = 0; i < 160; i++) {
    for (int j = 0; j < 91; j++) {
      tft.drawPixel(i, j, midbar_logo[i][j]);
    }
  }
  action_for_data_in_flash_menu(curr_key);
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
          cont_to_next = true;
        }

        if (curr_key == 1  && cont_to_next == false) {
          if (record_type == 0)
            select_login(1);
          cont_to_next = true;
        }

        if (curr_key == 2  && cont_to_next == false) {
          if (record_type == 0)
            select_login(2);
          cont_to_next = true;
        }

        if (curr_key == 3  && cont_to_next == false) {
          if (record_type == 0)
            select_login(3);
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
    delete_file("/L" + String(i + 1) + "_hash");
    delete_file("/L" + String(i + 1) + "_ttl");
    delete_file("/L" + String(i + 1) + "_usn");
    delete_file("/L" + String(i + 1) + "_psw");
    delete_file("/L" + String(i + 1) + "_wbs");
    delete_file("/C" + String(i + 1) + "_hash");
    delete_file("/C" + String(i + 1) + "_ttl");
    delete_file("/C" + String(i + 1) + "_hld");
    delete_file("/C" + String(i + 1) + "_nmr");
    delete_file("/C" + String(i + 1) + "_exp");
    delete_file("/C" + String(i + 1) + "_cvn");
    delete_file("/C" + String(i + 1) + "_pin");
    delete_file("/C" + String(i + 1) + "_zip");
    delete_file("/N" + String(i + 1) + "_hash");
    delete_file("/N" + String(i + 1) + "_ttl");
    delete_file("/N" + String(i + 1) + "_cnt");
    delete_file("/P" + String(i + 1) + "_hash");
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
  call_main_menu();
  delay(1);
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
