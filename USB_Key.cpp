#include "Keyboards.h"
#include <USB.h>
#include <USBHIDKeyboard.h>

extern const uint8_t KeyboardLayout_it_IT[];
extern const uint8_t KeyboardLayout_en_US[];

USBHIDKeyboard usbKeyboard;

void initUSB() {
    USB.begin();
    if (getKeyboardLayout() == KEYBOARD_LAYOUT_US) {
        usbKeyboard.begin(KeyboardLayout_en_US);
    } else {
        usbKeyboard.begin(KeyboardLayout_it_IT);
    }
}

void typeUSB(String text) {
    usbKeyboard.print(text);
}