#include <SPI.h>
#include <deprecated.h>
#include <MFRC522.h>
#include <MFRC522Extended.h>
#include <require_cpp11.h>


//Konfigurasi PIN
#define RST_PIN               D3  // Configurable, see typical pin layout above
#define SS_PIN                D8  // Configurable, see typical pin layout above
#define RELAY_PIN             D0

#define SECURITY_BLOCK_COUNT  3
#define BLOCK_SIZE            18

static byte keyA[MFRC522::MF_KEY_SIZE] = {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}; //KEY A
static byte keyB[MFRC522::MF_KEY_SIZE] = {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}; //KEY B
static byte secBlockData[3][BLOCK_SIZE] = {{0xF3,0xAE,0xCC,0xFE,0x6F,0x08,0x04,0x00,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69},
                                          {0x4E,0x57,0x49,0x2D,0x30,0x30,0x31,0x2D,0x32,0x34,0x30,0x37,0x32,0x30,0x32,0x34},
                                          {0x45,0x56,0x2D,0x30,0x31,0x30,0x30,0x4B,0x2D,0x32,0x33,0x30,0x37,0x33,0x42,0x34}};
bool relayStatus = false;

MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.

void setup() {
    Serial.begin(115200); // Initialize serial communications with the PC
    while (!Serial);      // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
    SPI.begin();          // Init SPI bus
    mfrc522.PCD_Init();   // Init MFRC522 card
    pinMode(RELAY_PIN, OUTPUT);
    digitalWrite(RELAY_PIN, HIGH); //ESP 32 Is Inverted
    Serial.println(relayStatus);
    Serial.println(F("Tempelkan kartu NFC !"));
}

void dumpByteArray(byte *buffer, byte bufferSize) {
    for (byte i = 0; i < bufferSize; i++) {
        Serial.print(buffer[i] < 0x10 ? " 0" : " ");
        Serial.print(buffer[i], HEX);
    }
}

bool authBlockData(byte buffer[], byte blockData[], byte bufferSize) {
  bool result = false;
  for (byte i = 0; i < bufferSize; i++) {
    Serial.print("Comparing Bit : ");
    Serial.print(buffer[i], HEX);
    Serial.print(" = ");
    Serial.print(blockData[i], HEX);
    Serial.println();
    if(buffer[i] !=  blockData[i]) {
      return false;
    }
  }
  return true;
}


bool authCardData() {
  bool result = false;
  MFRC522::StatusCode status;
  byte buffer[BLOCK_SIZE];
  byte byteCount = sizeof(buffer);
  MFRC522::MIFARE_Key keya;
  MFRC522::MIFARE_Key keyb;
  byte block = 0;

  Serial.print(F("Card UID:"));
  dumpByteArray(mfrc522.uid.uidByte, mfrc522.uid.size);
  Serial.println();
  Serial.print(F("PICC type: "));
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));
  
  for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
    keya.keyByte[i] = keyA[i];
  }
  for (byte i = 0; i < MFRC522::MF_KEY_SIZE; i++) {
    keyb.keyByte[i] = keyB[i];
  }
  
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &keya, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate Key A() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    mfrc522.PICC_HaltA();       // Halt PICC
    mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
    return false;
  }
  
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_B, block, &keyb, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate Key B() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    mfrc522.PICC_HaltA();       // Halt PICC
    mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
    return false;
  }

  
  for (byte i = 0; i < SECURITY_BLOCK_COUNT; i++) {
    status = mfrc522.MIFARE_Read(i, buffer, &byteCount);
    if (status != MFRC522::STATUS_OK) {
      Serial.print(F("MIFARE_Read() failed: "));
      Serial.println(mfrc522.GetStatusCodeName(status));
    }
    else {
      // Dump block data
      Serial.print(F("Block ")); Serial.print(i); Serial.print(F(":"));
      dumpByteArray(buffer, 16);
      Serial.println();
      if(!authBlockData(buffer, secBlockData[i], 16)){
        Serial.print(F("Unmatched"));
        mfrc522.PICC_HaltA();       // Halt PICC
        mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
        return false;
      }
      Serial.println("Matched");
      // Successful read
      result = true;
    }
  }
  mfrc522.PICC_HaltA();       // Halt PICC
  mfrc522.PCD_StopCrypto1();  // Stop encryption on PCD
  return result;
}

void loop() {
  if( ! relayStatus ){
    // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
    if ( ! mfrc522.PICC_IsNewCardPresent())
      return;
  
    // Select one of the cards
    if ( ! mfrc522.PICC_ReadCardSerial())
      return;
  
    if( ! authCardData() ){
      Serial.println(F("Authentification Unsuccess"));
      delay(500);
      return;
    }
    digitalWrite(RELAY_PIN, LOW);
    relayStatus = true;
    Serial.println(relayStatus);
    Serial.println(F("Success"));
  }
  //other function code here
}
