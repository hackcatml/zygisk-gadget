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

std::string readFileContents(const std::string& filePath) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
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

    return contents; // Return the C-style string
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
    // If there's a froda-gadget config file, remove it too.
    std::regex pattern("frida-gadget.*\\.config\\.so");
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
        std::string file_path_to_read = module_dir + std::string("/targetpkg");
        std::string target_package_name = readFileContents(file_path_to_read);

        if (strcmp(package_name, target_package_name.c_str()) == 0) {
            _enable_gadget_injection = true;

            _target_package_name = new char[strlen(target_package_name.c_str()) + 1];
            strcpy(_target_package_name, target_package_name.c_str());

            file_path_to_read = module_dir + std::string("/sleeptime");
            std::string time_to_sleep = readFileContents(file_path_to_read);
            _time_to_sleep = std::stoi(time_to_sleep);

#ifdef __aarch64__
            std::regex pattern("frida-gadget.*arm64\\.so");
#else
            std::regex pattern("frida-gadget.*arm\\.so");
#endif
            std::string frida_gadget_name = find_matching_file(module_dir, pattern);
            _frida_gadget_name = new char[strlen(frida_gadget_name.c_str()) + 1];
            strcpy(_frida_gadget_name, frida_gadget_name.c_str());

            std::string frida_gadget_path = module_dir + std::string("/") + frida_gadget_name;

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

            // check if there is a frida-gadget config file
            std::string frida_config_path = module_dir + std::string("/frida-gadget.config");
            std::ifstream file(frida_config_path);
            if (file) {
                bool frida_config_mode = true;
                write(fd, &frida_config_mode, sizeof(frida_config_mode));

                // send the frida-gadget config path string
                length = strlen(frida_config_path.c_str());
                write(fd, &length, sizeof(length));
                write(fd, frida_config_path.c_str(), length);

                // send the frida_config_name string
                std::string frida_config_name = frida_gadget_name.substr(0, frida_gadget_name.find_last_of('.')) + ".config.so";
                length = strlen(frida_config_name.c_str());
                write(fd, &length, sizeof(length));
                write(fd, frida_config_name.c_str(), length);
            } else {
                bool frida_config = false;
                write(fd, &frida_config, sizeof(frida_config));
            }

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

    std::string format = std::string("cp %s /data/data/%s/");

    // check frida_config_mode
    bool frida_config_mode;
    read(i, &frida_config_mode, sizeof(frida_config_mode));
    if (frida_config_mode) {
        // read the frida_config_path string
        read(i, &length, sizeof(length));
        char* frida_config_path = new char[length];
        read(i, frida_config_path, length);

        // read the frida_config_name string
        read(i, &length, sizeof(length));
        char* frida_config_name = new char[length];
        read(i, frida_config_name, length);

        // copy frida-gadget config file to the app data dir
        executeCommand(frida_config_path, package_name, (format + std::string(frida_config_name)).c_str());
    }

    // copy frida-gadget to the target package's data dir
    executeCommand(frida_gadget_path, package_name, format.c_str());
}

REGISTER_ZYGISK_MODULE(MyModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
