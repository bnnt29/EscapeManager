// Your secrets. EVERYTHING here is optional: leave a line empty to keep the default, or leave all empty and
// enter them later in the board's setup Wi-Fi ("EscapeSetup-<id>"). Keep your real values out of version control.
//
// Values stored on the board (setup form, manager "Geraete-Setup", serial commands) win over these.
// PlatformIO users: the untracked secrets.ini works as well; -D build flags win over the lines below.

#ifndef ESCAPE_WIFI_SSID
#define ESCAPE_WIFI_SSID ""             // Wi-Fi to join, e.g. "MyNetwork"
#endif
#ifndef ESCAPE_WIFI_PASSWORD
#define ESCAPE_WIFI_PASSWORD ""         // empty = open network, otherwise 8..63 characters
#endif
#ifndef ESCAPE_AUTH_TOKEN
#define ESCAPE_AUTH_TOKEN ""            // shared token of the installation, 8..128 characters (>= 20 recommended). Empty = public default
#endif
#ifndef ESCAPE_EDIT_TOKEN
#define ESCAPE_EDIT_TOKEN ""            // only holders may send plans to devices. Empty = the normal token may
#endif
#ifndef ESCAPE_SETUP_AP_PASSWORD
#define ESCAPE_SETUP_AP_PASSWORD ""     // password of the setup Wi-Fi, 8..63 characters. Empty = OPEN setup Wi-Fi
#endif
