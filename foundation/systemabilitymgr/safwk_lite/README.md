# safwk_lite

## Introduction

The Lite System Ability Framework (safwk_lite) component provides an empty process for running basic services.

## System Architecture

Figure 1 Service-oriented architecture


![](figures/en-us_image_0000001128146921.png)

-   Provider: a service provider that provides capabilities (external APIs) for the system.
-   Consumer: a service consumer that invokes the features (external APIs) provided by the service.
-   Samgr: an agency that manages capabilities provided by providers and helps consumers discover providers' capabilities.


## Directory Structure

The following table describes the directory structure of the safwk_lite source code.

**Table 1** Directory structure of the major source code

| Name                                                        | Description                                  |
| ------------------------------------------------------------ | -------------------------------------- |
| safwk_lite                                                   | Implementation of the foundation process.                    |
| bool Publish(sptr\<IRemoteObject> systemAbility);            | Publishes a system ability.                        |
| virtual void DoStartSAProcess(const std::string& profilePath) = 0; | Enables a system ability based on its profile.|

The source code directory structure of the safwk\_lite component is as follows:

```
├── BUILD.gn
├── readme.md
├── LICENSE
├── src
    └── main.c
```

## Usage

Add a service to the foundation process.

After writing the service information based on the service template, add the dependencies to the **BUILD.gn** file.

```
deps = [
  "${aafwk_lite_path}/services/abilitymgr_lite:abilityms",
  "${appexecfwk_lite_path}/services/bundlemgr_lite:bundlems",
  "//base/hiviewdfx/hilog_lite/frameworks/featured:hilog_shared",
  "//base/security/permission_lite/services/ipc_auth:ipc_auth_target",
  "//base/security/permission_lite/services/pms:pms_target",
  "//foundation/ability/dmsfwk_lite:dtbschedmgr",
  "//foundation/systemabilitymgr/samgr_lite/samgr_server:server",
]
```

## Repositories Involved

Samgr

[systemabilitymgr\_samgr\_lite](https://gitee.com/openharmony/systemabilitymgr_samgr_lite)

[systemabilitymgr\_samgr](https://gitee.com/openharmony/systemabilitymgr_samgr)

[systemabilitymgr\_safwk](https://gitee.com/openharmony/systemabilitymgr_safwk)

[**systemabilitymgr\_safwk\_lite**](https://gitee.com/openharmony/systemabilitymgr_safwk_lite)
