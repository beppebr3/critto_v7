#ifndef KEYBOARDS_H
#define KEYBOARDS_H

#include <Arduino.h>

enum KeyboardLayoutMode {
    KEYBOARD_LAYOUT_ITALIAN = 0,
    KEYBOARD_LAYOUT_US = 1
};

// Funzioni per l'USB
void initUSB();
void typeUSB(String text);

// Funzioni per il Bluetooth
void initBLE();
void typeBLE(String text);
bool isBLEConnected();

void setKeyboardLayout(KeyboardLayoutMode layout);
KeyboardLayoutMode getKeyboardLayout();

#endif