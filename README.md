# zygisk-gadget
A zygisk module loads frida-gadget

# Usage
## Normal mode
Frida-gadget will be loaded when the target package is launched.<br>
**1. Install the release file**

**2. Modify the target package name**<br>
Change the target package name to the one you want to load the frida-gadget into.<br>
The default package name is "com.android.chrome".<br>
If you launch Chrome, it will pause until you attach to it with the `frida -U Gadget` command.

You can change the package name with the following command on your device:<br>
`echo "com.android.vending" > /data/adb/modules/zygisk_gadget/targetpkg`<br>
The target app is now `Google Play Store`.

**3. Modify the sleep time as needed**<br>
`Sleep time` refers to the delay before loading the frida-gadget into the app process.<br>
Once the frida-gadget is loaded, the app process will pause until you attach to it with the "frida -U gadget" command.<br>
The default sleep time is 500000 microseconds (0.5 seconds).

If you wish to set it to 30 seconds (meaning you want to load the frida-gadget 30 seconds after the app has launched), change it with the following command:<br>
`echo "30000000" > /data/adb/modules/zygisk_gadget/sleeptime`<br>
Btw, don't put it on zero. It's too soon for that frida-gadget to load up, it will fail.

## Config file mode
This module supports a config file mode as described [here](https://frida.re/docs/gadget/)<br>
Follow the steps below.<br>
**1. Create `hluda-gadget.config` file in the module directory**<br>
For example,
`echo -e '{\n"interaction":{\n"type":"script",\n"path":"/data/local/tmp/myscript.js",\n"on_change":"reload"}\n}' > /data/adb/modules/zygisk_gadget/hluda-gadget.config`

**2. Put the script file at the path specified in `hluda-gadget.config`**<br>
For instance, create a myscript.js file with the following content. It's a simple frida script that logs a message.<br>
```javascript
Java.perform(function() {
  const Log = Java.use("android.util.Log");
  Log.d("[hackcatml]", " hello from myscript.js");
})
```
then adb push it to the specified path.<br>
`adb push myscript.js /data/local/tmp/`

**3. Launch the target app**<br>
The frida-gadget will be loaded in config file mode.<br>
You should see `hello from myscript.js` message in logcat. (tested on Chrome, sleep time set to 0.5 sec.)<br>
![image](https://github.com/hackcatml/zygisk-gadget/assets/75507443/6c59d37a-d3b4-486f-b58f-77e58a50bf1a)

# Build and Flash
Git clone this repo and open it in Android Studio.

Put the target package name in the "template/magisk_module/targetpkg" file.

Put the sleep time (in microseconds) before loading the frida-gadget in the "template/magisk_module/sleeptime" file.

Build and flash by "./gradlew :module:flashAndRebootRelease"

# Credits
[xDL](https://github.com/hexhacking/xDL)<br>
[Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper)<br>
[strongR-frida-android](https://github.com/hzzheyang/strongR-frida-android)
