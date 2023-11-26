#include <jni.h>
#include <thread>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <array>

#include "zygisk.hpp"
#include "log.h"
#include "xdl.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

const char* readFileContents(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        // Handle the error, e.g., by returning nullptr
        return nullptr;
    }

    std::stringstream buffer;
    buffer << file.rdbuf(); // Read the file contents into the buffer
    file.close();

    std::string contents = buffer.str(); // Convert the buffer to a string
    return contents.c_str(); // Return the C-style string
}

std::string getPathFromFd(int fd) {
    char buf[PATH_MAX];
    std::string fdPath = "/proc/self/fd/" + std::to_string(fd);
    ssize_t len = readlink(fdPath.c_str(), buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        return {buf};
    } else {
        // Handle error
        return "";
    }
}

void injection_thread(const char* target_package_name, int time_to_sleep) {
//    LOGD("frida-gadget injection thread start for %s", target_package_name);
    usleep(time_to_sleep);

    std::string gadget_path = std::string("/data/data/") +
                              std::string(target_package_name) +
#ifdef __aarch64__
                              std::string("/frida-gadget-16.1.7-android-arm64.so");
#else   // arm
                              std::string("/frida-gadget-16.1.7-android-arm.so");
#endif

    std::ifstream file(gadget_path);
    if (file) {
        LOGD("gadget is ready to load from %s", gadget_path.c_str());
    } else {
        LOGD("cannot find gadget in %s", gadget_path.c_str());
        return;
    }

    void* handle = xdl_open(gadget_path.c_str(), 1);
    if (handle) {
        LOGD("frida-gadget loaded");
        unlink(gadget_path.c_str());
    } else {
        LOGD("frida-gadget failed to load");
    }
}

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->_api = api;
        _env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        if (!args || !args->nice_name) {
            LOGE("Skip unknown process");
            return;
        }

        auto package_name = _env->GetStringUTFChars(args->nice_name, nullptr);

        std::string module_dir = getPathFromFd(_api->getModuleDir());
        std::string file_path_to_read = module_dir + std::string("/targetpkg");
        const char* target_package_name = readFileContents(file_path_to_read);

        if (strcmp(package_name, target_package_name) == 0) {
            enable_gadget_injection = true;

            _target_package_name = new char[strlen(target_package_name) + 1];
            strcpy(_target_package_name, target_package_name);

            file_path_to_read = module_dir + std::string("/sleeptime");
            const char* time_to_sleep = readFileContents(file_path_to_read);
            _time_to_sleep = std::stoi(time_to_sleep);

#ifdef __aarch64__
            std::string frida_gadget_path = module_dir + std::string("/frida-gadget-16.1.7-android-arm64.so");
#else   // arm
            std::string frida_gadget_path = module_dir + std::string("/frida-gadget-16.1.7-android-arm.so");
#endif

            int fd = _api->connectCompanion();
            // send the length of the string first
            size_t length = strlen(_target_package_name) + 1; // +1 for the null terminator
            write(fd, &length, sizeof(length));
            // send the target_package_name string
            write(fd, _target_package_name, length);

            // send the frida_gadget_path string
            length = strlen(frida_gadget_path.c_str());
            write(fd, &length, sizeof(length));
            write(fd, frida_gadget_path.c_str(), length);

            close(fd);
        }

        _env->ReleaseStringUTFChars(args->nice_name, package_name);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (enable_gadget_injection) {
            std::thread t(injection_thread, _target_package_name, _time_to_sleep);
            t.detach();
        }
    }

private:
    Api* _api{};
    JNIEnv* _env{};
    bool enable_gadget_injection{};
    char* _target_package_name{};
    int _time_to_sleep{};

};

static void executeCommand(const char* gadget_path, const char* package_name, const char* format) {
    char* command;
    int res = asprintf(&command, format, gadget_path, package_name);
    if (res == -1) {
        LOGD("Failed to build command string");
        return;
    }
    LOGD("command: %s", command);

    std::array<char, 128> buffer{};
    std::string result;
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        LOGD("Failed to run command");
        free(command);
        return;
    }

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
//    LOGD("result: %s", result.c_str());

    pclose(pipe);
    free(command);
}

static void companion_handler(int i) {
    LOGD("hello from companion_handler");

    size_t length;
    read(i, &length, sizeof(length));
    // allocate memory for the string
    char* package_name = new char[length];
    // read the package_name string
    read(i, package_name, length);

    // read the frida_gadget_path string
    read(i, &length, sizeof(length));
    char* frida_gadget_path = new char[length];
    read(i, frida_gadget_path, length);

    // copy frida-gadget to the target package's data dir
    executeCommand(frida_gadget_path, package_name, "cp %s /data/data/%s/");
}

REGISTER_ZYGISK_MODULE(MyModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
