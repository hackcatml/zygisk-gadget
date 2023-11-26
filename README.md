# zygisk-gadget
A zygisk module loads frida-gadget

# Usage
Git clone this repo.<br>

Put the target package name in the "template/magisk_module/targetpkg" file.<br>

Put the sleep time (in milliseconds) before loading the frida-gadget in the "template/magisk_module/sleeptime" file.<br>

Build and flash by "./gradlew :module:flashAndRebootRelease"<br>

After rebooting, launch the target app.<br>

Attach to the target app by "frida -U Gadget"<br>

# Credits
[xDL](https://github.com/hexhacking/xDL)<br>
[Zygisk-Il2CppDumper](https://github.com/Perfare/Zygisk-Il2CppDumper)
