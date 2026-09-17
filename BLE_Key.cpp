#include "Keyboards.h"
#include <BleKeyboard.h>

#define SHIFT           0x80
#define ALT_GR          0x40
#define ISO_KEY         0x64
#define ISO_REPLACEMENT 0x32

extern const uint8_t KeyboardLayout_it_IT[];
extern const uint8_t KeyboardLayout_en_US[];

BleKeyboard bleKeyboard("Cardputer Crypto", "M5Stack", 100);

void initBLE() {
    bleKeyboard.begin();
}

void typeBLE(String text) {
    if (text.length() == 0 || !bleKeyboard.isConnected()) {
        return;
    }

    KeyboardLayoutMode selectedLayout = getKeyboardLayout();
    const uint8_t* layout = (selectedLayout == KEYBOARD_LAYOUT_US) ? KeyboardLayout_en_US : KeyboardLayout_it_IT;

    for (size_t i = 0; i < text.length(); ++i) {
        unsigned char ch = (unsigned char)text[i];
        if (ch >= 128) {
            continue;
        }

        uint8_t mapped = layout[ch];
        if (mapped == 0) {
            continue;
        }

        uint8_t usage = mapped & ~(SHIFT | ALT_GR);
        if (usage == ISO_REPLACEMENT) {
            usage = ISO_KEY;
        }

        KeyReport report = {0};
        if (mapped & SHIFT) {
            report.modifiers |= 0x02;
        }
        if (mapped & ALT_GR) {
            report.modifiers |= 0x40;
        }
        report.keys[0] = usage;

        bleKeyboard.sendReport(&report);

        KeyReport release = {0};
        bleKeyboard.sendReport(&release);
        delay(5);
    }
}

bool isBLEConnected() {
    return bleKeyboard.isConnected();
}