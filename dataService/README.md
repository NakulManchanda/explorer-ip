# Description
The source code and build instructions for network data service in ZSS.

# Steps To Build
  - In the `build/` directory, git clone https://github.com/zowe/zss/ OR create a symbolic link to already existing zss repository, e.g. using `ln -s /path/to/existing/zss build/zss`.
  - Run the `build/build.sh` script.
  - The build should succeed and create a /lib folder in the git root directory, which contains a compiled dll (.so).

# File Structure Example
install-dir
  - dataService
    - build
      - build.sh
      - pluginAPI.x
      - tmp
      - zss
    - deploy.sh
    - src
      - ipExplorerDataService.c
  - lib
    - ipExplorer.so
  - pluginDefinition.json
  - webClient
  - ...

# Troubleshooting
To turn on logging, add the following snippet into your zluxserver.json file:

```
"logLevels": {
   "org.zowe.explorer-ip": 4
}
```

The number after the plugin identifier represents the level of logging. This is read into the server at startup.
