# zygisk-gadget
A zygisk module loads frida-gadget

# Usage

Two ways to use<br>
(1) Modify [release](https://github.com/hackcatml/zygisk-gadget/releases/)
```text
Download release

Unzip and modify the targetpkg, sleeptime file 
(can also change the frida-gadget file to whichever version you prefer)

Zip (e.g., zip -r zygisk-gadget.zip ./*)

Install the module using magisk manager 
```

(2) Build and Flash
```text
Git clone this repo and open it in Android Studio.

Put the target package name in the "template/magisk_module/targetpkg" file.

Put the sleep time (in milliseconds) before loading the frida-gadget in the "template/magisk_module/sleeptime" file.

Build and flash by "./gradlew :module:flashAndRebootRelease"

After rebooting, launch the target app.

Attach to the target app by "frida -U Gadget"
```

# Credits
[xDL](https://github.com/hexhacking/xDL)<br>
[Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper)<br>
[strongR-frida-android](https://github.com/hzzheyang/strongR-frida-android)