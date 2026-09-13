/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 *
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PLUGIN_MANAGER_H
#define PLUGIN_MANAGER_H

#include <atomic>
#include <memory>
#include <mutex>
#include <string>

#include "ihistogram_plugin.h"

namespace OHOS {
namespace histogram {

/**
 * @class PluginManager
 * @brief Manages the dynamic loading, registration, and unloading of histogram plugins.
 * * This class provides a thread-safe mechanism to handle shared library (.so) operations
 * and ensures that plugin instances are correctly managed across the system lifecycle.
 */
class PluginManager {
public:
    /**
     * @brief Access the global singleton instance of PluginManager.
     * @return Reference to the thread-safe PluginManager instance.
     */
    static PluginManager &GetInstance();

    PluginManager();
    ~PluginManager();

    /**
     * @brief Performs a lazy load of the default histogram plugin.
     * @return True if the plugin is successfully loaded or already exists.
     */
    bool LazyLoadPlugin();

    /**
     * @brief Loads the plugin from the specified path only if it hasn't been initialized.
     * Uses double-checked locking for high concurrency performance.
     * @param path The filesystem path to the shared library.
     */
    bool LoadPluginIfNeeded(const std::string &path);

    /**
     * @brief Forces the loading of a plugin from a specific path.
     * @param path The filesystem path to the shared library.
     */
    bool LoadPlugin(const std::string &path);

    /**
     * @brief Manually registers an existing plugin instance.
     * Typically used for dependency injection or testing purposes.
     * @param plugin Pointer to the IHistogramPlugin implementation.
     */
    void RegisterPlugin(IHistogramPlugin *plugin);

    /**
     * @brief Retrieves the currently active plugin instance.
     * @return A pointer to the active plugin, or nullptr if none is loaded.
     * @note This is a lock-free fast path using atomic memory_order_acquire.
     */
    inline IHistogramPlugin *GetPlugin() const
    {
        return plugin_.load(std::memory_order_acquire);
    }

    /**
     * @brief Unloads the current plugin and closes the library handle.
     * @return True if the unloading process completed without errors.
     */
    bool UnloadPlugin();

    /**
     * @brief Cleans up and unloads all managed plugin resources.
     */
    void UnloadAllPlugins();

private:
    /** @brief Internal implementation of the plugin loading logic (mutex-protected). */
    bool LoadPluginLocked(const std::string &path);

    /** @brief Resolves factory symbols via dlsym and instantiates the plugin class. */
    bool ResolveAndCreatePluginLocked(const std::string &path);

    /** @brief Resets internal state variables and pointers to their default values. */
    void ResetPluginLocked();

private:
    /** @brief Guards library loading and unloading operations. */
    std::mutex mutex_;

    /** @brief Opaque handle to the loaded dynamic library (from dlopen). */
    void *pluginHandle_ = nullptr;

    /** @brief Cached path of the currently loaded shared library. */
    std::string pluginPath_;

    /** @brief Atomic pointer to the plugin instance for thread-safe access. */
    std::atomic<IHistogramPlugin *> plugin_ { nullptr };

    /** @brief Atomic flag indicating whether the initialization process has completed. */
    std::atomic<bool> pluginHasInit_ { false };
};

} // namespace histogram
} // namespace OHOS

#endif // PLUGIN_MANAGER_H