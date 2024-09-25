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
#include "nlohmann/json.hpp"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

using json = nlohmann::json;

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

std::string getPathFromFd(int fd) {
    char buf[PATH_MAX];
    std::string fdPath = "/proc/self/fd/" + std::to_string(fd);
    ssize_t len = readlink(fdPath.c_str(), buf, sizeof(buf) - 1);
    close(fd);
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

void injection_thread(const char* target_package_name, const char* frida_gadget_name, uint time_to_sleep) {
    LOGD("Frida-gadget injection thread start for %s, gadget name: %s, usleep: %d", target_package_name, frida_gadget_name, time_to_sleep);
    usleep(time_to_sleep);

    std::string app_data_dir = std::string("/data/data/") +
                               std::string(target_package_name) +
                               std::string("/");
    std::string gadget_path = app_data_dir +
                              std::string(frida_gadget_name);

    std::ifstream file(gadget_path);
    if (file) {
        LOGD("Gadget is ready to load from %s", gadget_path.c_str());
    } else {
        LOGD("Cannot find gadget in %s", gadget_path.c_str());
        return;
    }

    void* handle = xdl_open(gadget_path.c_str(), 1);
    if (handle) {
        LOGD("Frida-gadget loaded");
    } else {
        LOGD("Frida-gadget failed to load");
    }

    unlink(gadget_path.c_str());
    // If there's a frida-gadget config file, remove it too.
    std::regex pattern(".*-gadget.*\\.config\\.so$");
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

        std::string config_file_path = module_dir + "/config";
        writeString(fd, config_file_path);

        std::string target_package_name = readString(fd);

        if (strcmp(package_name, target_package_name.c_str()) == 0) {
            LOGD("Enable gadget injection %s", package_name);
            _enable_gadget_injection = true;

            _target_package_name = strdup(target_package_name.c_str());

            uint delay;
            read(fd, &delay, sizeof(delay));
            _delay = delay;

            std::string frida_gadget_name = readString(fd);
            _frida_gadget_name = strdup(frida_gadget_name.c_str());

            close(fd);
        } else {
            _api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            close(fd);
        }
        _env->ReleaseStringUTFChars(args->nice_name, package_name);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (_enable_gadget_injection) {
            std::thread t(injection_thread, _target_package_name, _frida_gadget_name, _delay);
            t.detach();
        }
    }

private:
    Api* _api{};
    JNIEnv* _env{};
    bool _enable_gadget_injection{};
    char* _target_package_name{};
    uint _delay{};
    char* _frida_gadget_name{};

};

json get_json(const std::string& path) {
    std::ifstream file(path);
    if (file.is_open()) {
        json j;
        file >> j;
        file.close();
        return j;
    } else {
        LOGD("Failed to open %s", path.c_str());
        return nullptr;
    }
}

static void executeCommand(const char* gadget_path, const char* package_name, const char* format) {
    char* command;
    int res = asprintf(&command, format, gadget_path, package_name);
    if (res == -1) {
        LOGD("Failed to build command string");
        return;
    }
    LOGD("Command: %s", command);

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
    std::string config_file_path = readString(i);

    json j = get_json(config_file_path);
    if (j == nullptr) {
        return;
    }
    std::string target_package_name = j["package"]["name"];
    uint delay = j["package"]["delay"];
    bool frida_config_mode = j["package"]["mode"]["config"];

    writeString(i, target_package_name);
    write(i, &delay, sizeof(delay));

#ifdef __arm__
    std::regex frida_gadget_pattern(".*-gadget.*arm\\.so$");
#elifdef __aarch64__
    std::regex frida_gadget_pattern(".*-gadget.*arm64\\.so$");
#elifdef __i386__
    std::regex frida_gadget_pattern(".*-gadget.*x86\\.so$");
#elifdef __x86_64__
    std::regex frida_gadget_pattern(".*-gadget.*x86_64\\.so$");
#endif
    std::string module_dir = config_file_path.substr(0, config_file_path.rfind('/'));;
    std::string frida_gadget_name = find_matching_file(module_dir, frida_gadget_pattern);
    writeString(i, frida_gadget_name);
    std::string frida_gadget_path = module_dir + "/" + frida_gadget_name;

    std::string format = "cp %s /data/data/%s/";

    if (frida_config_mode) {
        std::regex frida_config_pattern(".*-gadget\\.config$");
        std::string frida_config_name = find_matching_file(module_dir, frida_config_pattern);
        std::string frida_config_path = module_dir + "/" + frida_config_name;

        std::string new_frida_config_name = frida_gadget_name.substr(0, frida_gadget_name.find_last_of('.')) + ".config.so";
        executeCommand(frida_config_path.c_str(), target_package_name.c_str(), (format + new_frida_config_name).c_str());
    }

    executeCommand(frida_gadget_path.c_str(), target_package_name.c_str(), format.c_str());
}

REGISTER_ZYGISK_MODULE(MyModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
