#include <Arduino.h>
#include <M5Unified.h>
#include <M5Cardputer.h>
#include <Preferences.h>
#include <esp_system.h>
#include "mbedtls/aes.h"
#include "mbedtls/base64.h"
#include "Keyboards.h" 

enum AppState { SELECT_OUTPUT, SELECT_KEY_MODE, INPUT_KEY_MANUAL, VIEW_KEY, INPUT_TEXT, WAITING_BLE_CONNECTION };
AppState currentState = SELECT_OUTPUT;
KeyboardLayoutMode currentKeyboardLayout = KEYBOARD_LAYOUT_ITALIAN;
bool useUSB = true;
bool bleInitialized = false;
bool usbInitialized = false;
String currentKey = "";
String currentText = "";
bool cryptoInfoVisible = false;
bool cryptoReady = false;
bool txReady = false;
int lastResetReason = 0;
String lastDbgEvent = "";
Preferences dbgPrefs;

static const char* getLayoutDisplayName(KeyboardLayoutMode layout) {
    return layout == KEYBOARD_LAYOUT_US ? "US" : "IT";
}

static void drawFrame() {
    int w = M5Cardputer.Display.width();
    int h = M5Cardputer.Display.height();
    M5Cardputer.Display.drawRect(2, 2, w - 4, h - 4, GREEN);
}

static void drawIndicator(const char* label, bool active, int x, int y, int w) {
    M5Cardputer.Display.fillRoundRect(x, y, w, 14, 3, active ? GREEN : DARKGREY);
    M5Cardputer.Display.setTextColor(active ? BLACK : LIGHTGREY);
    M5Cardputer.Display.setTextSize(1);
    int labelW = M5Cardputer.Display.textWidth(label);
    int contentX = x + (w - labelW) / 2;
    M5Cardputer.Display.setCursor(contentX, y + 2);
    M5Cardputer.Display.print(label);
}

static void drawBottomBar() {
    int w = M5Cardputer.Display.width();
    int h = M5Cardputer.Display.height();
    int borderInset = 10;
    int gap = 5;
    int barY = h - 22;
    int btW = 42;
    int usbW = 54;
    int layoutW = 36;
    int encW = 40;
    int txW = 36;
    int totalW = btW + gap + usbW + gap + layoutW + gap + encW + gap + txW;
    int centerX = (w - totalW) / 2;

    int barLeft = centerX;
    int maxBarLeft = borderInset;
    int maxBarRight = w - borderInset;
    if (barLeft < maxBarLeft) barLeft = maxBarLeft;
    if (barLeft + totalW > maxBarRight) barLeft = maxBarRight - totalW;

    drawIndicator("BT", (bleInitialized && isBLEConnected()), barLeft, barY, btW);
    drawIndicator("USB", useUSB, barLeft + btW + gap, barY, usbW);
    drawIndicator(getLayoutDisplayName(currentKeyboardLayout), true, barLeft + btW + gap + usbW + gap, barY, layoutW);
    drawIndicator("ENC", cryptoReady, barLeft + btW + gap + usbW + gap + layoutW + gap, barY, encW);
    drawIndicator("TX", txReady, barLeft + btW + gap + usbW + gap + layoutW + gap + encW + gap, barY, txW);
}

static void drawCryptoInfoScreen() {
    int w = M5Cardputer.Display.width();
    int h = M5Cardputer.Display.height();
    int contentX = 16;
    M5Cardputer.Display.setTextSize(2);
    M5Cardputer.Display.setTextColor(GREEN, BLACK);
    M5Cardputer.Display.setCursor((w - 94) / 2, 18);
    M5Cardputer.Display.println("CRYPTO");

    M5Cardputer.Display.setTextSize(1);
    M5Cardputer.Display.setTextColor(WHITE, BLACK);
    M5Cardputer.Display.setCursor(contentX, 52);
    M5Cardputer.Display.println("AES-128 / PKCS#7 / Base64");
    M5Cardputer.Display.setCursor(contentX, 66);
    M5Cardputer.Display.println("Key: manual or random");
    M5Cardputer.Display.setCursor(contentX, 80);
    M5Cardputer.Display.println("Output: USB or BLE");
    M5Cardputer.Display.setCursor(contentX, 94);
    M5Cardputer.Display.println("0: close info");

    M5Cardputer.Display.setTextColor(GREEN, BLACK);
    M5Cardputer.Display.setCursor(contentX, h - 34);
    M5Cardputer.Display.println("[0] Close");
}

void setKeyboardLayout(KeyboardLayoutMode layout) {
    currentKeyboardLayout = layout;
    dbgPrefs.putUInt("keyboard_layout", (uint32_t)layout);
}

KeyboardLayoutMode getKeyboardLayout() {
    return currentKeyboardLayout;
}

// #region agent log
static void agentLog(const char* hypothesisId, const char* location, const char* message) {
    char buf[400];
    snprintf(buf, sizeof(buf),
        "{\"sessionId\":\"bb501b\",\"runId\":\"post-fix\",\"hypothesisId\":\"%s\",\"location\":\"%s\",\"message\":\"%s\",\"timestamp\":%lu,\"data\":{\"heap\":%u,\"minHeap\":%u,\"psram\":%u,\"resetReason\":%d,\"usbInit\":%d,\"bleInit\":%d,\"useUSB\":%d,\"state\":%d}}",
        hypothesisId, location, message, (unsigned long)millis(),
        (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMinFreeHeap(),
        (unsigned)ESP.getPsramSize(),
        lastResetReason, usbInitialized ? 1 : 0, bleInitialized ? 1 : 0,
        useUSB ? 1 : 0, (int)currentState);
    Serial.println(buf);
    lastDbgEvent = String(message);
    dbgPrefs.putString("last", lastDbgEvent);
    dbgPrefs.putUInt("heap", ESP.getFreeHeap());
}
// #endregion

class CryptoProvider {
public:
    static String generateRandomKey(int length = 16) {
        const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
        String key = "";
        for (int i = 0; i < length; i++) {
            key += charset[esp_random() % (sizeof(charset) - 1)];
        }
        return key;
    }

    static String encryptSymmetricAndBase64(String plainText, String key) {
        mbedtls_aes_context aes;
        mbedtls_aes_init(&aes);
        unsigned char keyBuffer[16] = {0};
        memcpy(keyBuffer, key.c_str(), min((size_t)16, key.length()));
        mbedtls_aes_setkey_enc(&aes, keyBuffer, 128);

        int paddingLen = 16 - (plainText.length() % 16);
        int paddedSize = plainText.length() + paddingLen;
        unsigned char* inputBuffer = new unsigned char[paddedSize];
        unsigned char* outputBuffer = new unsigned char[paddedSize];
        
        memcpy(inputBuffer, plainText.c_str(), plainText.length());
        for(int i = plainText.length(); i < paddedSize; i++) inputBuffer[i] = (unsigned char)paddingLen;

        for(int i = 0; i < paddedSize; i += 16) mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, inputBuffer + i, outputBuffer + i);

        size_t b64Len = 0;
        mbedtls_base64_encode(nullptr, 0, &b64Len, outputBuffer, paddedSize);
        unsigned char* b64Buffer = new unsigned char[b64Len];
        mbedtls_base64_encode(b64Buffer, b64Len, &b64Len, outputBuffer, paddedSize);
        String result = String((char*)b64Buffer);

        delete[] inputBuffer; delete[] outputBuffer; delete[] b64Buffer;
        mbedtls_aes_free(&aes);
        return result;
    }
};

// Unified function to clear and redraw the screen without flicker.
void drawUI() {
    int w = M5Cardputer.Display.width();
    int h = M5Cardputer.Display.height();
    int margin = 8;
    int titleY = 16;
    int contentX = margin + 16;
    int safeBottom = h - 58;
    int primaryY = 54;
    int supportY = 88;
    int itemGap = 12;

    M5Cardputer.Display.fillScreen(BLACK);
    drawFrame();

    if (cryptoInfoVisible) {
        drawCryptoInfoScreen();
        drawBottomBar();
        return;
    }

    M5Cardputer.Display.setTextColor(WHITE, BLACK);
    M5Cardputer.Display.setTextSize(2);

    switch (currentState) {
        case SELECT_OUTPUT:
            M5Cardputer.Display.setTextSize(2);
            M5Cardputer.Display.setCursor((w - 74) / 2, titleY);
            M5Cardputer.Display.setTextColor(GREEN, BLACK);
            M5Cardputer.Display.println("OUTPUT");
            M5Cardputer.Display.setTextColor(WHITE, BLACK);
            M5Cardputer.Display.setTextSize(1.5);
            M5Cardputer.Display.setCursor(contentX, primaryY);
            M5Cardputer.Display.println("[1] USB HID");
            M5Cardputer.Display.setCursor(contentX, primaryY + itemGap);
            M5Cardputer.Display.println("[2] BLE");
            M5Cardputer.Display.setCursor(contentX, primaryY + itemGap * 2);
            M5Cardputer.Display.println("[I] IT   [U] US");
            M5Cardputer.Display.setCursor(contentX, primaryY + itemGap * 3);
            M5Cardputer.Display.println("[0] Crypto info");
            break;

        case SELECT_KEY_MODE:
            M5Cardputer.Display.setTextSize(2);
            M5Cardputer.Display.setCursor((w - 48) / 2, titleY);
            M5Cardputer.Display.setTextColor(GREEN, BLACK);
            M5Cardputer.Display.println("KEY");
            M5Cardputer.Display.setTextColor(WHITE, BLACK);
            M5Cardputer.Display.setTextSize(1.5);
            M5Cardputer.Display.setCursor(contentX, primaryY);
            M5Cardputer.Display.println("[M] Manual");
            M5Cardputer.Display.setCursor(contentX, primaryY + itemGap);
            M5Cardputer.Display.println("[G] Random");
            M5Cardputer.Display.setCursor(contentX, primaryY + itemGap * 2);
            M5Cardputer.Display.println("[OPT] Back");
            break;

        case INPUT_KEY_MANUAL:
            M5Cardputer.Display.setTextSize(2);
            M5Cardputer.Display.setCursor((w - 48) / 2, titleY);
            M5Cardputer.Display.setTextColor(GREEN, BLACK);
            M5Cardputer.Display.println("KEY");
            M5Cardputer.Display.setTextColor(WHITE, BLACK);
            M5Cardputer.Display.setTextSize(1.5);
            M5Cardputer.Display.setCursor(contentX, primaryY);
            M5Cardputer.Display.print("Key: ");
            M5Cardputer.Display.setTextColor(ORANGE, BLACK);
            M5Cardputer.Display.println(currentKey);
            M5Cardputer.Display.setTextColor(WHITE, BLACK);
            M5Cardputer.Display.setCursor(contentX, supportY);
            M5Cardputer.Display.println("[ENTER] Confirm");
            M5Cardputer.Display.setCursor(contentX, supportY + itemGap);
            M5Cardputer.Display.println("[OPT] Back");
            break;

        case VIEW_KEY:
            M5Cardputer.Display.setTextSize(2);
            M5Cardputer.Display.setCursor((w - 48) / 2, titleY);
            M5Cardputer.Display.setTextColor(GREEN, BLACK);
            M5Cardputer.Display.println("KEY");
            M5Cardputer.Display.setTextColor(WHITE, BLACK);
            M5Cardputer.Display.setTextSize(1.5);
            M5Cardputer.Display.setCursor(contentX, primaryY);
            M5Cardputer.Display.print("Key: ");
            M5Cardputer.Display.setTextColor(ORANGE, BLACK);
            M5Cardputer.Display.println(currentKey);
            M5Cardputer.Display.setTextColor(WHITE, BLACK);
            M5Cardputer.Display.setCursor(contentX, supportY);
            M5Cardputer.Display.println("[TAB] Send key");
            M5Cardputer.Display.setCursor(contentX, supportY + itemGap);
            M5Cardputer.Display.println("[ENTER] Message");
            M5Cardputer.Display.setCursor(contentX, supportY + itemGap * 2);
            M5Cardputer.Display.println("[OPT] Back");
            break;

        case INPUT_TEXT:
            M5Cardputer.Display.setTextSize(2);
            M5Cardputer.Display.setCursor((w - 56) / 2, titleY);
            M5Cardputer.Display.setTextColor(GREEN, BLACK);
            M5Cardputer.Display.println("TEXT");
            M5Cardputer.Display.setTextColor(WHITE, BLACK);
            M5Cardputer.Display.setTextSize(1.5);
            M5Cardputer.Display.setCursor(contentX, primaryY);
            M5Cardputer.Display.println(currentText);
            M5Cardputer.Display.setCursor(contentX, supportY);
            M5Cardputer.Display.println("[ENTER] Send");
            M5Cardputer.Display.setCursor(contentX, supportY + itemGap);
            M5Cardputer.Display.println("[OPT] Back");
            break;

        case WAITING_BLE_CONNECTION:
            M5Cardputer.Display.setTextSize(2);
            M5Cardputer.Display.setCursor((w - 52) / 2, titleY);
            M5Cardputer.Display.setTextColor(GREEN, BLACK);
            M5Cardputer.Display.println("BLE");
            M5Cardputer.Display.setTextColor(WHITE, BLACK);
            M5Cardputer.Display.setTextSize(1.5);
            M5Cardputer.Display.setCursor(contentX, primaryY);
            M5Cardputer.Display.println("Waiting connection");
            M5Cardputer.Display.setCursor(contentX, primaryY + itemGap);
            M5Cardputer.Display.println("Pair phone/PC");
            M5Cardputer.Display.setCursor(contentX, primaryY + itemGap * 2);
            M5Cardputer.Display.println("with HID keyboard");
            M5Cardputer.Display.setCursor(contentX, supportY + itemGap);
            M5Cardputer.Display.println("[OPT] Cancel");
            break;
    }

    // Reserve the lower area for the footer; do not overwrite it with any black band.
    drawBottomBar();
}

void typeString(String data) {
    if (data.length() == 0) {
        return;
    }

    if (useUSB) { 
        typeUSB(data); 
        return;
    }

    if (!bleInitialized || !isBLEConnected()) {
        M5Cardputer.Display.setTextColor(RED);
        M5Cardputer.Display.println("\nBLE not connected!");
        delay(1500);
        return;
    }

    const size_t maxChunk = 64;
    for (size_t i = 0; i < data.length(); i += maxChunk) {
        size_t chunkLen = min((size_t)maxChunk, (size_t)(data.length() - i));
        String chunk = data.substring(i, i + chunkLen);
        typeBLE(chunk);
        delay(10);
    }
}

void setup() {
    Serial.begin(115200);
    auto cfg = M5.config();
    M5Cardputer.begin(cfg, true);

    lastResetReason = (int)esp_reset_reason();
    dbgPrefs.begin("dbgbb", false);
    currentKeyboardLayout = (KeyboardLayoutMode)dbgPrefs.getUInt("keyboard_layout", KEYBOARD_LAYOUT_ITALIAN);
    setKeyboardLayout(currentKeyboardLayout);
    lastDbgEvent = dbgPrefs.getString("last", "");
    uint32_t prevHeap = dbgPrefs.getUInt("heap", 0);
    bool startBLE = dbgPrefs.getBool("startBLE", false);

    // #region agent log
    {
        char boot[480];
        snprintf(boot, sizeof(boot),
            "{\"sessionId\":\"bb501b\",\"runId\":\"post-fix\",\"hypothesisId\":\"D\",\"location\":\"critto_v7.ino:setup\",\"message\":\"boot\",\"timestamp\":%lu,\"data\":{\"heap\":%u,\"minHeap\":%u,\"psram\":%u,\"resetReason\":%d,\"prevHeap\":%u,\"startBLE\":%d,\"prevEvent\":\"%s\"}}",
            (unsigned long)millis(), (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMinFreeHeap(),
            (unsigned)ESP.getPsramSize(), lastResetReason, (unsigned)prevHeap,
            startBLE ? 1 : 0, lastDbgEvent.c_str());
        Serial.println(boot);
        Serial.flush();
    }
    // #endregion

    M5Cardputer.Display.setRotation(1);
    setKeyboardLayout(currentKeyboardLayout);

    if (startBLE) {
        dbgPrefs.putBool("startBLE", false);
        useUSB = false;
        M5Cardputer.Display.fillScreen(BLACK);
        M5Cardputer.Display.setCursor(0, 0);
        M5Cardputer.Display.setTextColor(YELLOW);
        M5Cardputer.Display.println("Starting Bluetooth...");
        // #region agent log
        agentLog("C", "critto_v7.ino:setup", "before_initBLE_setup");
        Serial.flush();
        // #endregion
        unsigned long t0 = millis();
        initBLE();
        bleInitialized = true;
        // #region agent log
        {
            char after[420];
            snprintf(after, sizeof(after),
                "{\"sessionId\":\"bb501b\",\"runId\":\"post-fix\",\"hypothesisId\":\"C\",\"location\":\"critto_v7.ino:setup\",\"message\":\"after_initBLE_setup\",\"timestamp\":%lu,\"data\":{\"heap\":%u,\"minHeap\":%u,\"elapsedMs\":%lu,\"usbInit\":0,\"bleInit\":1}}",
                (unsigned long)millis(), (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMinFreeHeap(),
                millis() - t0);
            Serial.println(after);
            Serial.flush();
            lastDbgEvent = "after_initBLE_setup";
            dbgPrefs.putString("last", lastDbgEvent);
            dbgPrefs.putUInt("heap", ESP.getFreeHeap());
        }
        // #endregion
        currentState = SELECT_KEY_MODE;
    }

    delay(200);
}

void loop() {
    M5Cardputer.update(); 
    
    static AppState lastState = (AppState)-1;
    
    // Redraw the screen only when the menu changes.
    if (currentState != lastState) {
        drawUI();
        lastState = currentState;
    }

    if (currentState == WAITING_BLE_CONNECTION && isBLEConnected()) {
        currentState = SELECT_KEY_MODE;
        drawUI();
        lastState = currentState;
    }

    // Read the keyboard only when a key is actually pressed to avoid screen glitches.
    if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
        Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

        bool toggleCryptoInfo = false;
        for (char key : status.word) {
            if (key == '0') {
                toggleCryptoInfo = true;
                break;
            }
        }

        if (toggleCryptoInfo) {
            cryptoInfoVisible = !cryptoInfoVisible;
            drawUI();
            return;
        }

        cryptoReady = false;
        txReady = false;

        if (status.opt) {
            // #region agent log
            agentLog("F", "critto_v7.ino:loop", "opt_back");
            // #endregion
            if (currentState == WAITING_BLE_CONNECTION) {
                currentState = SELECT_OUTPUT;
            }
            else if (currentState == SELECT_KEY_MODE) currentState = SELECT_OUTPUT;
            else if (currentState == INPUT_KEY_MANUAL) currentState = SELECT_KEY_MODE;
            else if (currentState == VIEW_KEY) currentState = SELECT_KEY_MODE;
            else if (currentState == INPUT_TEXT) currentState = VIEW_KEY;
            delay(20);
            return;
        }

        switch (currentState) {
            case SELECT_OUTPUT:
                for (auto c : status.word) {
                    if (c == '1') {
                        useUSB = true;
                        if (bleInitialized) {
                            // #region agent log
                            agentLog("B", "critto_v7.ino:loop", "restart_for_usb");
                            Serial.flush();
                            // #endregion
                            dbgPrefs.putBool("startBLE", false);
                            delay(50);
                            ESP.restart();
                        }
                        if (!usbInitialized) {
                            // #region agent log
                            agentLog("A", "critto_v7.ino:loop", "before_initUSB");
                            Serial.flush();
                            // #endregion
                            initUSB();
                            usbInitialized = true;
                            // #region agent log
                            agentLog("A", "critto_v7.ino:loop", "after_initUSB");
                            Serial.flush();
                            // #endregion
                        }
                        currentState = SELECT_KEY_MODE;
                    } else if (c == '2') {
                        useUSB = false;
                        M5Cardputer.Display.println("\nStarting Bluetooth...");
                        if (usbInitialized) {
                            // #region agent log
                            agentLog("B", "critto_v7.ino:loop", "restart_for_ble");
                            Serial.flush();
                            // #endregion
                            dbgPrefs.putBool("startBLE", true);
                            delay(50);
                            ESP.restart();
                        }
                        if (!bleInitialized) {
                            // #region agent log
                            agentLog("B", "critto_v7.ino:loop", "before_initBLE");
                            Serial.flush();
                            // #endregion
                            unsigned long t0 = millis();
                            initBLE();
                            unsigned long elapsed = millis() - t0;
                            bleInitialized = true;
                            // #region agent log
                            {
                                char after[420];
                                snprintf(after, sizeof(after),
                                    "{\"sessionId\":\"bb501b\",\"runId\":\"post-fix\",\"hypothesisId\":\"C\",\"location\":\"critto_v7.ino:loop\",\"message\":\"after_initBLE\",\"timestamp\":%lu,\"data\":{\"heap\":%u,\"minHeap\":%u,\"resetReason\":%d,\"usbInit\":0,\"bleInit\":1,\"elapsedMs\":%lu}}",
                                    (unsigned long)millis(), (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMinFreeHeap(),
                                    lastResetReason, elapsed);
                                Serial.println(after);
                                Serial.flush();
                                lastDbgEvent = "after_initBLE";
                                dbgPrefs.putString("last", lastDbgEvent);
                                dbgPrefs.putUInt("heap", ESP.getFreeHeap());
                            }
                            // #endregion
                            delay(200);
                        }
                        currentState = WAITING_BLE_CONNECTION;
                    } else if (c == 'i' || c == 'I') {
                        currentKeyboardLayout = KEYBOARD_LAYOUT_ITALIAN;
                        setKeyboardLayout(currentKeyboardLayout);
                        if (useUSB && usbInitialized) {
                            initUSB();
                        }
                        drawUI();
                    } else if (c == 'u' || c == 'U') {
                        currentKeyboardLayout = KEYBOARD_LAYOUT_US;
                        setKeyboardLayout(currentKeyboardLayout);
                        if (useUSB && usbInitialized) {
                            initUSB();
                        }
                        drawUI();
                    }
                }
                break;

            case SELECT_KEY_MODE:
                for (auto c : status.word) {
                    if (c == 'm' || c == 'M') { currentKey = ""; currentState = INPUT_KEY_MANUAL; }
                    else if (c == 'g' || c == 'G') { currentKey = CryptoProvider::generateRandomKey(); currentState = VIEW_KEY; }
                }
                break;

            case INPUT_KEY_MANUAL:
                for (auto c : status.word) currentKey += c;
                if (status.del && currentKey.length() > 0) currentKey.remove(currentKey.length() - 1);
                
                if (status.enter) {
                    currentState = VIEW_KEY;
                } else {
                    drawUI(); // Refresh the screen with typed keys.
                }
                break;

            case VIEW_KEY:
                // Now correctly reads the Cardputer TAB key.
                if (status.tab) {
                    if (currentKey.length() == 0) {
                        M5Cardputer.Display.setTextColor(YELLOW);
                        M5Cardputer.Display.println("\nNo key configured: nothing to send");
                        M5Cardputer.Display.setTextColor(WHITE);
                    } else {
                        typeString(currentKey);
                        M5Cardputer.Display.setTextColor(YELLOW);
                        M5Cardputer.Display.println("\n-> Key sent!");
                        M5Cardputer.Display.setTextColor(WHITE);
                    }
                }
                else if (status.enter) {
                    currentText = ""; 
                    currentState = INPUT_TEXT;
                }
                break;

            case WAITING_BLE_CONNECTION:
                if (isBLEConnected()) {
                    currentState = SELECT_KEY_MODE;
                }
                break;

            case INPUT_TEXT:
                for (auto c : status.word) currentText += c;
                if (status.del && currentText.length() > 0) currentText.remove(currentText.length() - 1);
                
                if (status.enter && currentText.length() > 0) {
                    M5Cardputer.Display.setTextColor(YELLOW);
                    if (currentKey.length() == 0) {
                        M5Cardputer.Display.println("\nSending plaintext...");
                        typeString(currentText);
                    } else {
                        M5Cardputer.Display.println("\nEncrypting...");
                        typeString(CryptoProvider::encryptSymmetricAndBase64(currentText, currentKey));
                    }
                    
                    M5Cardputer.Display.setTextColor(GREEN);
                    M5Cardputer.Display.println("Sent!");
                    currentText = "";
                    cryptoReady = true;
                    txReady = true;
                    delay(1500);
                    drawUI(); // Clear the screen for the next message.
                } else {
                    drawUI(); // Refresh the screen with typed keys in real time.
                }
                break;
        }
    }
    
    delay(20); // Mantiene in vita l'hardware senza far crashare il Watchdog
}