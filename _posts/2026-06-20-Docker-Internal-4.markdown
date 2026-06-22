---
layout: post
title:  "Docker Internal (4)"
categories: Container
---

- Part1: [Docker Internal (1)]({% post_url 2026-05-27-Docker-Internal-1 %})
- Part2: [Docker Internal (2)]({% post_url 2026-06-02-Docker-Internal-2 %})
- Part3: [Docker Internal (3)]({% post_url 2026-06-04-Docker-Internal-3 %})
- Part4: [Docker Internal (4)]({% post_url 2026-06-20-Docker-Internal-4 %})

In the final post, we'll cover how vendors like NVIDIA or AMD integrate their code into the Docker system, including hardcoding in the moby code and designing a runtime. We will also show a vulnerability I found in the NVIDIA runtime to let you know what kind of code patterns may lead to problems.

## 1. Docker Interface

### 1.1. Runtime

Docker provides a custom runtime implementation. For example, if you run `docker run --runtime=aaabbb ubuntu`, the JSON config inside the container-creation request body will include `"Runtime": "aaabbb"`.

The runtime name is used to look up the runtime object in `Get()` of `dockerd` (moby/moby). If you don't provide a runtime name, the default runtime, `"runc"`, is used [1].

``` go
// daemon/runtime_unix.go
func (r *runtimes) Get(name string) (string, any, error) {
    if name == "" {
        name = r.Default // [1] "runc"
    }

    rt := r.configured[name] // if you use --runtime=aaabbb, the name here will be "aaabbb"
    // [...]
    return rt.Shim, rt.Opts, nil
}
```

`setupRuntimes()` is called to setup the runtime objects. It creates the objects based on `cfg.Runtimes`, which comes from the file `/etc/docker/daemon.json`. `defaultV2ShimConfig()` is called with the path name [2], and it assigns the path name to `Opts.BinaryName` [3] and returns the wrapped shim object.

``` go
// daemon/runtime_unix.go
func setupRuntimes(cfg *config.Config) (runtimes, error) {
    // [...]
    for name, rt := range cfg.Runtimes {
        if rt.Path != "" {
            // [...]
            binaryName := rt.Path
            c = defaultV2ShimConfig(cfg, binaryName) // [2]
        }
        // [...]
        newrt.configured[name] = c
        // [...]
    }
    // [...]
}

func defaultV2ShimConfig(conf *config.Config, runtimePath string) *shimConfig {
    shim := &shimConfig{
        Shim: plugins.RuntimeRuncV2,
        Opts: &runcoptions.Options{
            BinaryName:    runtimePath, // [3]
            Root:          filepath.Join(conf.ExecRoot, "runtime-"+defaultRuntimeName),
            // [...]
        },
    }
    // [...]
    return shim
}
```

When creating a container, the shim daemon runs `options.BinaryName`, which is the path name of user's runtime.

``` go
// cmd/containerd-shim-runc-v2/runc/container.go
func newInit(/*...*/) {
    // [...]
    runtime := process.NewRunc(options.Root, path, namespace, options.BinaryName, options.SystemdCgroup)
    // [...]
}
```

I think most of the time a vendor's runtime implementation is **a wrapper around `runc`**. It **modifies the generated OCI spec** to mount more devices, get more capabilities and insert some hooks. In the end, it still executes `runc` to start a container.

### 1.2. GPUs

If you run `docker run --gpus=all ubuntu`, `docker` (the docker CLI) sends a run-container request to `dockerd` asking for GPU devices to add to the container, which corresponds to the JSON field below in the request body.

``` json
"DeviceRequests": [
    {
        "Driver": "",
        "Count": -1,
        "DeviceIDs": null,
        "Capabilities": [["gpu"]],
        "Options": {}
    }
]
```

On the `dockerd` side, when handling the device requests [1], `handleDevice()` iterates the requested drivers [2] and updates the OCI spec [3].

``` go
// daemon/oci_linux.go
func WithDevices(daemon *Daemon, c *container.Container) coci.SpecOpts {
    return func(ctx context.Context, _ coci.Client, _ *containers.Container, s *coci.Spec) error {
        // [...]
        for _, req := range c.HostConfig.DeviceRequests { // [1]
            if err := daemon.handleDevice(req, s); err != nil { // <--------
                return err
            }
        }
        return nil
    }
}

// daemon/devices.go
func (daemon *Daemon) handleDevice(req container.DeviceRequest, spec *specs.Spec) error {
    if req.Driver == "" {
        // [...]
        for driver, dd := range deviceDrivers { // [2]
            if selected := dd.capset.Match(req.Capabilities); selected != nil {
                // [...]
                return dd.updateSpec(spec, &deviceInstance{req: req, selectedCaps: selected}) // [3]
            }
        }
    }
}
```

It looks like only two GPU drivers are supported now: NVIDIA [4] and AMD [5].

``` go
// daemon/devices.go
func registerDeviceDriver(name string, d *deviceDriver) {
    deviceDrivers[name] = d
}

// daemon/devices_linux.go
func RegisterGPUDeviceDrivers(cdiCache *cdi.Cache) {
    // [...]
    if nvidiaDrivers := getNVIDIADeviceDrivers(); len(nvidiaDrivers) > 0 {
        for name, driver := range nvidiaDrivers {
            registerDeviceDriver(name, driver) // [4]
        }
        return
    }

    // [...]
    if amdDriver := getAMDDeviceDrivers(cdiCache); amdDriver != nil {
        registerDeviceDriver("amd", amdDriver) // [5]
        return
    }
}
```

Here we take NVIDIA as an example (which matches our topic!). It registers three drivers: `"nvidia.cdi"` [6], `"nvidia.runtime-hook"` [7] and `"nvidia"` [8]. `"nvidia"` covers cdi and runtime-hook, and each of them has **its own spec updater** [9, 10].

``` go
func getNVIDIADeviceDrivers() map[string]*deviceDriver {
    var composite firstSuccessfulUpdater
    nvidiaDrivers := make(map[string]*deviceDriver)

    if _, err := exec.LookPath(nvidiaCDIHookExecutableName); err == nil {
        // [...]
        cdiDeviceDriver := &deviceDriver{
            updateSpec: (&cdiDeviceInjector{
                defaultCDIDeviceKind: "nvidia.com/gpu",
            }).injectDevices, // [9]
        }
        nvidiaDrivers["nvidia.cdi"] = cdiDeviceDriver // [6]
        composite = append(composite, cdiDeviceDriver.updateSpec)
    }

    if _, err := exec.LookPath(nvidiaContainerRuntimeHookExecutableName); err == nil {
        // [...]
        runtimeHookDeviceDriver := &deviceDriver{
            updateSpec: injectNVIDIARuntimeHook, // [10]
        }
        nvidiaDrivers["nvidia.runtime-hook"] = runtimeHookDeviceDriver // [7]
        composite = append(composite, runtimeHookDeviceDriver.updateSpec)
    }

    capset := capabilities.Set{"gpu": struct{}{}, "nvidia": struct{}{}}
    for c := range allNvidiaCaps {
        capset[c] = struct{}{}
    }
    nvidiaDrivers["nvidia"] = &deviceDriver{ // [8]
        capset:     capset,
        updateSpec: composite.updateSpec,
    }

    return nvidiaDrivers
}
```

Since the request doesn't specify which driver is used (`"Driver": ""`), all drivers are iterated over. Once the matching one is found, it **updates the OCI spec** based on the vendor's updater implementation.

### 1.3. Hook

The OCI runtime spec defines container lifecycle hooks via the `Hooks` struct (repo `opencontainers/runtime-spec`). Each field is a list of **programs the runtime executes at a specific point** in the container's lifecycle. We can find the related code in the [opencontainers/runc](https://github.com/opencontainers/runc) repository.

``` go
// vendor/github.com/opencontainers/runtime-spec/specs-go/config.go
type Hooks struct {
    Prestart []Hook `json:"prestart,omitempty"`
    CreateRuntime []Hook `json:"createRuntime,omitempty"`
    CreateContainer []Hook `json:"createContainer,omitempty"`
    StartContainer []Hook `json:"startContainer,omitempty"`
    Poststart []Hook `json:"poststart,omitempty"`
    Poststop []Hook `json:"poststop,omitempty"`
}
```

There are six hook types, and they are all defined in the OCI spec (`config.json`) and loaded in `createHooks()`.

``` go
// libcontainer/specconv/spec_linux.go
func createHooks(rspec *specs.Spec, config *configs.Config) {
    config.Hooks = configs.Hooks{}
    if rspec.Hooks != nil {
        for _, h := range rspec.Hooks.Prestart {
            cmd := createCommandHook(h)
            config.Hooks[configs.Prestart] = append(config.Hooks[configs.Prestart], configs.NewCommandHook(cmd))
        }
        for _, h := range rspec.Hooks.CreateRuntime {
            cmd := createCommandHook(h)
            config.Hooks[configs.CreateRuntime] = append(config.Hooks[configs.CreateRuntime], configs.NewCommandHook(cmd))
        }
        for _, h := range rspec.Hooks.CreateContainer {
            cmd := createCommandHook(h)
            config.Hooks[configs.CreateContainer] = append(config.Hooks[configs.CreateContainer], configs.NewCommandHook(cmd))
        }
        for _, h := range rspec.Hooks.StartContainer {
            cmd := createCommandHook(h)
            config.Hooks[configs.StartContainer] = append(config.Hooks[configs.StartContainer], configs.NewCommandHook(cmd))
        }
        for _, h := range rspec.Hooks.Poststart {
            cmd := createCommandHook(h)
            config.Hooks[configs.Poststart] = append(config.Hooks[configs.Poststart], configs.NewCommandHook(cmd))
        }
        for _, h := range rspec.Hooks.Poststop {
            cmd := createCommandHook(h)
            config.Hooks[configs.Poststop] = append(config.Hooks[configs.Poststop], configs.NewCommandHook(cmd))
        }
    }
}

func createCommandHook(h specs.Hook) *configs.Command {
    cmd := &configs.Command{
        Path: h.Path,
        Args: h.Args,
        Env:  h.Env,
    }
    // [...]
    return cmd
}
```

The actual `config.json` looks like:

``` json
{
  ...
  "hooks": {
    "startContainer": [
      {
        "path": "/hook-1",
        "args": ["aaa", "bbb"],
        "env": ["myenv=123"],
      },

      {
        "path": "/hook-2",
        "args": ["aaa", "bbb"],
        "env": ["myenv=456"],
      },
    ],

    "createContainer": [
      ...
    ]
  }
}
```

These hooks are triggered in the following order:

```
create -> [Prestart] -> [CreateRuntime] -> [CreateContainer] ->
start -> [StartContainer] -> [Poststart] -> (container is running) ->
delete -> [Poststop]
```

## 2. NVIDIA Container Toolkit

The NVIDIA Container Toolkit is an [open source project](https://github.com/NVIDIA/nvidia-container-toolkit) owned by NVIDIA, and it allows NVIDIA GPU users to build and run GPU-accelerated containers.

It implements a container runtime (`nvidia-container-runtime`) to intercept requests from the shim daemon to allow some utilities to be exported to container. The runtime also inserts several hooks.

Let's first see how `nvidia-container-runtime` works!

### 2.1. Runtime & Hooks

After installing the tools, you can see the NVIDIA runtime has been registered in `/etc/docker/daemon.json`. It means you can run a command like `docker run --runtime=nvidia ubuntu` to use NVIDIA toolkit inside the container.

``` json
{
    "default-runtime": "",
    "runtimes": {
        "nvidia": {
            "args": [],
            "path": "nvidia-container-runtime"
        }
    }
}
```

Instead of `runc`, `nvidia-container-runtime` is executed to start the container. It loads the NVIDIA runtime config from `config.toml` and calls `newNVIDIAContainerRuntime()` [2] to apply its runtime modifications to the OCI spec. In the end, `runtime.Exec()` is called [3] to reload the OCI spec and execute the lower-level runtime to load the container, which is `runc`.

``` go
// cmd/nvidia-container-runtime/main.go
func main() {
    r := runtime.New()
    err := r.Run(os.Args) // <--------
    // [...]
}

// internal/runtime/runtime.go
func (r rt) Run(argv []string) (rerr error) {
    cfg, err := config.GetConfig() // [1], fullpath: "/etc/nvidia-container-runtime/config.toml"
    
    // [...]
    // resolve path

    // [...]
    runtime, err := newNVIDIAContainerRuntime(r.logger, driver, cfg, argv) // [2]

    // [...]
    return runtime.Exec(argv) // [3]
}
```

`newNVIDIAContainerRuntime()` creates a spec modifier, a `Factory` object [4], and wraps it into a runtime object (`r`) [5].

``` go
// internal/runtime/runtime_factory.go
import (
    // [...]
    "github.com/NVIDIA/nvidia-container-toolkit/internal/modifier"
    // [...]
)

func newNVIDIAContainerRuntime(logger logger.Interface, driver *root.Driver, cfg *config.Config, argv []string) (oci.Runtime, error) {
    // [...]
    specModifier, err := newSpecModifier(logger, driver, cfg, ociSpec) // <--------
    // [...]
    r := oci.NewModifyingRuntimeWrapper( // [5]
        // [...]
        specModifier,
    )
}

func newSpecModifier(logger logger.Interface, driver *root.Driver, cfg *config.Config, ociSpec oci.Spec) (oci.SpecModifier, error) {
    return modifier.New( // <--------
        // [...]
    )
}

// internal/modifier/factory.go
func New(opts ...Option) (oci.SpecModifier, error) {
    f := createFactory(opts...) // <--------
    // [...]
    return f, nil
}

func createFactory(opts ...Option) *Factory {
    f := &Factory{} // [4]
    // [...]
    return f
}
```

`runtime.Exec()` is quite complex. The `r.modify()` call reloads the OCI spec [6]. Internally, it iterates the list entries returned from `f.create()` [7] and calls their modify handlers [8].

``` go
// internal/oci/runtime_modifier.go
func (r *modifyingRuntimeWrapper) Exec(args []string) error {
    if HasCreateSubcommand(args) {
        // [...]
        err := r.modify() // [6]
        // [...]
    }
    // [...]
    return r.runtime.Exec(args)
}

func (r *modifyingRuntimeWrapper) modify() error {
    _, err := r.ociSpec.Load()
    err = r.ociSpec.Modify(r.modifier) // <--------
    err = r.ociSpec.Flush()
}

// internal/oci/spec_memory.go
func (s *memorySpec) Modify(m SpecModifier) error {
    // [...]
    return m.Modify(s.Spec) // <--------
}

// internal/oci/spec.go
func (ms SpecModifiers) Modify(s *specs.Spec) error {
    for _, m := range ms {
        // [...]
        if err := m.Modify(s); err != nil { // <--------
            // [...]
        }
    }
    // [...]
}

// internal/modifier/factory.go
func (f *Factory) Modify(s *specs.Spec) error {
    m, err := f.create() // [7]
    // [...]
    return m.Modify(s) // <--------
}

// internal/modifier/list.go
func (m list) Modify(spec *specs.Spec) error {
    for _, mm := range m {
        // [...]
        err := mm.Modify(spec) // [8]
        // [...]
    }
    return nil
}
```

The factory creation function first gets supported modifier types [9] based on the runtime mode (`"legacy"`, `"csv"`, `"cdi"` and `"jit-cdi"`). The supported types are a string array, where each corresponds to a modifier object.

For example, if the modifier type is `"mode"` [10] and the runtime type is `"legacy"` [11], a `stableRuntimeModifier` is used [12], and its handler `Modify()` injects a prestart hook into the OCI spec [13].

``` go
// internal/modifier/factory.go
func (f *Factory) create() (oci.SpecModifier, error) {
    var modifiers list
    for _, modifierType := range supportedModifierTypes(f.runtimeMode) { // [9]
        switch modifierType {
        case "mode": // [10]
            modeModifier, err := f.newModeModifier() // <--------
            // [...]
            modifiers = append(modifiers, modeModifier)
        // [...]
        }
    }
    return modifiers, nil
}

// internal/modifier/mode.go
func (f *Factory) newModeModifier() (oci.SpecModifier, error) {
    switch f.runtimeMode {
    case info.LegacyRuntimeMode: // [11]
        return f.newStableRuntimeModifier(), nil // <--------
    // [...]
    }
}

// internal/modifier/stable.go
func (f *Factory) newStableRuntimeModifier() oci.SpecModifier {
    m := stableRuntimeModifier{ // [12]
        // [...]
        nvidiaContainerRuntimeHookPath: f.cfg.NVIDIAContainerRuntimeHookConfig.Path,
    }
    return &m
}

func (m stableRuntimeModifier) Modify(spec *specs.Spec) error {
    // [...]
    path := m.nvidiaContainerRuntimeHookPath
    args := []string{filepath.Base(path)}
    // [...]
    spec.Hooks.Prestart = append(spec.Hooks.Prestart, specs.Hook{ // [13]
        Path: path,
        Args: append(args, "prestart"),
    })
    // [...]
}
```

### 2.2. OCI Driver

In the section `1.2. GPUs`, we introduced how the `--gpus=...` option may apply a vendor's modification on the OCI spec. Here we continue to discuss the NVIDIA case.

The updater for the NVIDIA CDI driver is `injectDevices()`, while `injectNVIDIARuntimeHook()` is for the NVIDIA runtime driver. We will analyze how they work separately!

#### 2.2.1. CDI Driver

`injectDevices()` internally dispatches the request to the CDI driver [1], which is registered during the startup of `dockerd` [2].

``` go
// daemon/devices_nvidia_linux.go
func (i *cdiDeviceInjector) injectDevices(s *specs.Spec, dev *deviceInstance) error {
    deviceIDs, err := getRequestedDevicesIDs(dev.req) // deviceIDs == {"all"}
    cdiDeviceDriver := deviceDrivers["cdi"]
    // [...]
    for _, deviceID := range deviceIDs {
        // normalize from "all" to "nvidia.com/gpu=all"
        cdiDeviceIDs = append(cdiDeviceIDs, i.normalizeDeviceID(deviceID))
    }
    // [...]
    return cdiDeviceDriver.updateSpec(s, &deviceInstance{ // [1]
        req: container.DeviceRequest{
            // [...]
            DeviceIDs:    cdiDeviceIDs,
            // [...]
        },
    })
}

// daemon/cdi.go
func (cli *daemonCLI) start(ctx context.Context) (retErr error) {
    // [...]
    if cdiEnabled(cli.Config) {
        cdiCache = daemon.RegisterCDIDriver(cli.Config.CDISpecDirs...) // <--------
    }
    // [...]
}

func RegisterCDIDriver(cdiSpecDirs ...string) *cdi.Cache {
    for i, dir := range cdiSpecDirs {
        if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
            cdiSpecDirs[i], err = filepath.EvalSymlinks(dir)
            // [...]
        }
    }
    driver, cache := newCDIDeviceDriver(cdiSpecDirs...)
    registerDeviceDriver("cdi", driver) // [2]
    return cache
}
```

The default directories of the CDI spec are **`/etc/cdi`** and **`/var/run/cdi`**, and we can find that there is a file `/etc/cdi/nvidia.yaml` describing the OCI spec modification details. It defines what kind it is (`nvidia.com/gpu`), and also includes the hooks to be injected!

``` yaml
---
cdiVersion: 0.5.0
kind: nvidia.com/gpu
devices:
    - name: "0"
      containerEdits:
        deviceNodes:
            - path: /dev/nvidia0
              major: 195
              fileMode: 438
              permissions: rwm
            ...
        hooks:
            - hookName: createContainer
              path: /usr/bin/nvidia-cdi-hook
              args:
                - nvidia-cdi-hook
                - create-symlinks
                - --link
                - ../card2::/dev/dri/by-path/pci-0000:01:00.0-card
                - --link
                - ../renderD129::/dev/dri/by-path/pci-0000:01:00.0-render
              env:
                - NVIDIA_CTK_DEBUG=false
...
```

So how are these CDI drivers loaded and used? We can further trace `newCDIDeviceDriver()` and find that `InjectDevices()` is called with device names [3].

``` go
// daemon/cdi.go
func newCDIDeviceDriver(cdiSpecDirs ...string) (*deviceDriver, *cdi.Cache) {
    // [...]
    return &deviceDriver{
        updateSpec:  c.injectCDIDevices, // <--------
        // [...]
    }, cache
}

func (c *cdiHandler) injectCDIDevices(s *specs.Spec, dev *deviceInstance) error {
    // [...]
    cdiDeviceNames := dev.req.DeviceIDs // {"nvidia.com/gpu=all"}
    _, err := c.registry.InjectDevices(s, cdiDeviceNames...) // [3]
}
```

The implementation of `InjectDevices()` is defined in another project **"container-device-interface"** (or a standard), whose GitHub repository is [cncf-tags/container-device-interface](https://github.com/cncf-tags/container-device-interface).

Its CLI utilities provides multiple APIs to interact with CDI specs, and `InjectDevices()` is used to edit the original spec based on the CDI config of the targeted device.

It first iterates over all passed devices [4] and gets their specs [5], then resolves where to edit [6], and finally applies the changes to the OCI spec file [7].

``` go
// vendor/tags.cncf.io/container-device-interface/pkg/cdi/cache.go
func (c *Cache) InjectDevices(ociSpec *oci.Spec, devices ...string) ([]string, error) {
    edits := &ContainerEdits{}
    // [...]
    for _, device := range devices { // [4]
        d := c.devices[device] // device == "nvidia.com/gpu=all" here
        // [...]
        if _, ok := specs[d.GetSpec()]; !ok { // [5]
            // [...]
        }
        edits.Append(d.edits()) // [6]
    }

    if err := edits.Apply(ociSpec); err != nil { // [7]
        // [...]
    }
}
```

To summarize, the `docker` option `--gpus=all` is internally converted to `{"nvidia.com/gpu=all"}` for CDI, and files inside the spec directories (`/etc/cdi`) are read to find the matching kind `"nvidia.com/gpu"` and name `"all"`. Finally, the changes are applied to original OCI spec.

``` yaml
cdiVersion: 0.5.0
kind: nvidia.com/gpu
devices:
    - name: "0"
    ...
    - name: GPU-XXXX
    ...
    - name: all
    ...
...
```

#### 2.2.2. Runtime Driver 

The updater of the runtime driver is `injectNVIDIARuntimeHook()`, and it only injects a container prestart hook [1], which calls the command `nvidia-container-runtime-hook prestart`.

``` go
// daemon/devices_nvidia_linux.go
func injectNVIDIARuntimeHook(s *specs.Spec, dev *deviceInstance) error {
    // [...]
    path, err := exec.LookPath(nvidiaContainerRuntimeHookExecutableName) // "nvidia-container-runtime-hook"
    // [...]
    s.Hooks.Prestart = append(s.Hooks.Prestart, specs.Hook{ // [1]
        Path: path,
        Args: []string{
            nvidiaContainerRuntimeHookExecutableName,
            "prestart",
        },
        Env: os.Environ(),
    })
    // [...]
}
```

Surprisingly, NVIDIA's runtime (`nvidia-container-runtime`) tries to do OCI spec modifications, but these edits have almost all been done by `dockerd` if the CLI is executed with the `--gpus=all` option.

### 2.3. Vulnerability

This part is pending a response from the NVIDIA Security Team. I will publish the details once the issue has been fixed.

## 3. Summary

This series is called "Docker Internal", and it includes an introduction to the Docker system architecture (1), attack surface exploration during pulling an image (2), how a container is loaded (3), and finally vendors' modifications (4). We also use a vulnerability in the NVIDIA Toolkit as an example, showing the vulnerable code pattern. I hope you enjoyed it and learned something new!
