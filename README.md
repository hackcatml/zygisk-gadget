# zygisk-gadget
A zygisk module loads frida-gadget

# Usage
- **Install the release file and reboot**<br>
  `zygisk-gadget` tool will be placed in `/data/local/tmp/`<br>
```shell
/data/local/tmp/zygisk-gadget -h                                                                                       
Usage: ./zygisk-gadget -p <packageName> <option(s)>
 Options:
  -d, --delay <microseconds>             Delay in microseconds before loading frida-gadget
  -c, --config                           Activate config mode (default: false)
  -h, --help                             Show help
```

## Normal mode
Frida-gadget will be loaded when the target package is launched.<br>
e.g., `/data/local/tmp/zygisk-gadget -p com.android.chrome -d 300000`

## Config file mode
This module supports a config file mode as described [here](https://frida.re/docs/gadget/)<br>
Create `frida-gadget.config` file in the module directory (`/data/adb/modules/zygisk_gadget`) and then use `zygisk-gadget` tool with the config option<br>
e.g., `/data/local/tmp/zygisk-gadget -p com.android.chrome -d 300000 -c`

# Build and Flash
Git clone this repo and open it in Android Studio.

Build and flash by "./gradlew :module:flashAndRebootRelease"

# Credits
[xDL](https://github.com/hexhacking/xDL)<br>
[Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper)<br>
[Ajeossida](https://github.com/hackcatml/ajeossida)
