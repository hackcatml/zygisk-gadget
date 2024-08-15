#include <jni.h>
#include <thread>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <array>
#include <filesystem>
#include <regex>

#include "zygisk.hpp"
#include "log.h"
#include "xdl.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

void writeString(int fd, const std::string& str) {
    size_t length = str.size() + 1;
    write(fd, &length, sizeof(length));
    write(fd, str.c_str(), length);
}

std::string readString(int fd) {
    size_t length;
    read(fd, &length, sizeof(length));
    std::vector<char> buffer(length);
    read(fd, buffer.data(), length);
    return {buffer.data()};
}

std::string readFileContents(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        LOGW("cannot open %s", filePath.c_str());
        return "";
    }

    std::stringstream buffer;
    buffer << file.rdbuf(); // Read the file contents into the buffer
    file.close();

    std::string contents = buffer.str(); // Convert the buffer to a string
    // Remove newlines and whitespace
    contents.erase(std::remove_if(contents.begin(), contents.end(), [](unsigned char x) {
        return std::isspace(x);
    }), contents.end());

    return contents;
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

namespace fs = std::filesystem;
std::string find_matching_file(const fs::path& directory, const std::regex& pattern) {
    for (const auto& entry : fs::directory_iterator(directory)) {
        const auto& path = entry.path();
        const auto& filename = path.filename().string();

        if (std::regex_search(filename, pattern)) {
            return filename;
        }
    }
    return ""; // Return an empty string if no match is found
}

void injection_thread(const char* target_package_name, const char* frida_gadget_name, int time_to_sleep) {
    LOGD("frida-gadget injection thread start for %s, gadget name: %s, usleep: %d", target_package_name, frida_gadget_name, time_to_sleep);
    usleep(time_to_sleep);

    std::string app_data_dir = std::string("/data/data/") +
                               std::string(target_package_name) +
                               std::string("/");
    std::string gadget_path = app_data_dir +
                              std::string(frida_gadget_name);

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
    } else {
        LOGD("frida-gadget failed to load");
    }

    unlink(gadget_path.c_str());
    // If there's a frida-gadget config file, remove it too.
    std::regex pattern("hluda-gadget.*\\.config\\.so");
    std::string frida_config_name = find_matching_file(app_data_dir, pattern);
    if (!frida_config_name.empty()) {
        std::string frida_config_path = app_data_dir + frida_config_name;
        unlink(frida_config_path.c_str());
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
        int fd = _api->connectCompanion();

        std::string targetpkg_file_path_to_read = module_dir + "/targetpkg";
        writeString(fd, targetpkg_file_path_to_read);
        std::string target_package_name = readString(fd);

        if (strcmp(package_name, target_package_name.c_str()) == 0) {
            LOGD("enable gadget injection %s", package_name);
            _enable_gadget_injection = true;

            _target_package_name = strdup(target_package_name.c_str());

            std::string sleeptime_file_path_to_read = module_dir + "/sleeptime";
            writeString(fd, sleeptime_file_path_to_read);
            _time_to_sleep = std::stoi(readString(fd));

            writeString(fd, module_dir);
            std::string frida_gadget_name = readString(fd);
            _frida_gadget_name = strdup(frida_gadget_name.c_str());

            std::string frida_gadget_path = module_dir + "/" + frida_gadget_name;
            writeString(fd, frida_gadget_path);

            std::string frida_config_path = module_dir + "/hluda-gadget.config";
            writeString(fd, frida_config_path);

            bool frida_config_mode;
            read(fd, &frida_config_mode, sizeof(frida_config_mode));

            if (frida_config_mode) {
                std::string frida_config_name = frida_gadget_name.substr(0, frida_gadget_name.find_last_of('.')) + ".config.so";
                writeString(fd, frida_config_name);
            }
            close(fd);
        } else {
            _api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            close(fd);
        }
        _env->ReleaseStringUTFChars(args->nice_name, package_name);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (_enable_gadget_injection) {
            std::thread t(injection_thread, _target_package_name, _frida_gadget_name, _time_to_sleep);
            t.detach();
        }
    }

private:
    Api* _api{};
    JNIEnv* _env{};
    bool _enable_gadget_injection{};
    char* _target_package_name{};
    int _time_to_sleep{};
    char* _frida_gadget_name{};

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
    std::string targetpkg_file_path_to_read = readString(i);
    std::string target_package_name = readFileContents(targetpkg_file_path_to_read);
    writeString(i, target_package_name);

    std::string sleeptime_file_path_to_read = readString(i);
    if (sleeptime_file_path_to_read.empty())
        return;

    LOGD("hello from companion_handler");
    std::string time_to_sleep = readFileContents(sleeptime_file_path_to_read);
    writeString(i, time_to_sleep);

#ifdef __aarch64__
    std::regex pattern("hluda-gadget.*arm64\\.so");
#else
    std::regex pattern("hluda-gadget.*arm\\.so");
#endif
    std::string module_dir = readString(i);
    std::string frida_gadget_name = find_matching_file(module_dir, pattern);
    writeString(i, frida_gadget_name);

    std::string frida_gadget_path = readString(i);
    std::string frida_config_path = readString(i);

    std::ifstream file(frida_config_path);
    bool frida_config_mode = file.good();
    write(i, &frida_config_mode, sizeof(frida_config_mode));

    std::string format = "cp %s /data/data/%s/";

    if (frida_config_mode) {
        std::string frida_config_name = readString(i);
        executeCommand(frida_config_path.c_str(), target_package_name.c_str(), (format + frida_config_name).c_str());
    }

    executeCommand(frida_gadget_path.c_str(), target_package_name.c_str(), format.c_str());
}

REGISTER_ZYGISK_MODULE(MyModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
