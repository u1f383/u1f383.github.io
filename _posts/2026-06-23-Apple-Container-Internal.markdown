---
layout: post
title:  "Apple Container Internal"
categories: Container
---

One day I found Apple has its own container implementation, which is an open source project called [apple/container](https://github.com/apple/container). I was so curious about how it works and then spent a weekend tracing its internals. This post is a simple analysis of it.

## 1. Overview

Basically, the architecture of Apple's container is quite different from Docker Engine. Because Apple doesn't provide isolation mechanisms like namespace or cgroup, it leverages **Linux VM** to run containers, which means every container is running inside its own virtual machine. The hypervisor is not the most common one, QEMU-KVM. Actually, it is Apple's virtualization framework (a library), which internally uses **hardware virtualization**.

When starting the container manager daemon, an XPC server **`com.apple.container.apiserver` (`container-apiserver`)** is listening to manage all containers. When a container is created, another XPC server **`com.apple.container.runtime.container-runtime-linux.<uuid>` (`container-runtime-linux`)** is spawned for that container. Since Apple's virtualization mechanism is an in-process VM implementation, the runtime process not only **acts as a hypervisor** but also **runs the container inside the VM**.

The architecture is as follows:

```
  +------------------+
  |  container CLI   |   container run / start / ...
  +--------+---------+
           | XPC
           v
  +------------------------------------------------------------+
  |  container-apiserver                                       |
  |                                                            |
  |  (XPC: com.apple.container.apiserver)                      |
  |                                                            |
  |  Manages all containers / images / networks / volumes      |
  +-------+----------------------------------+-----------------+
          | spawns one per container         |
          v (XPC)                            v (XPC)
  +----------------------------+  +----------------------------+
  | container-runtime-linux #A |  | container-runtime-linux #B |
  |                            |  |                            |
  | (XPC: ...container-runtime |  | (XPC: ...container-runtime |
  |      -linux.<uuid-A>)      |  |      -linux.<uuid-B>)      |
  |                            |  |                            |
  | (Virtualization.framework, |  | (Virtualization.framework, |
  |  in-process, hardware virt)|  |  in-process, hardware virt)|
  |                            |  |                            |
  | +------------------------+ |  | +------------------------+ |
  | |    Linux VM (guest)    | |  | |    Linux VM (guest)    | |
  | |                        | |  | |                        | |
  | |  vminit                | |  | |  vminit                | |
  | |    +-- container proc  | |  | |    +-- container proc  | |
  | +------------------------+ |  | +------------------------+ |
  +----------------------------+  +----------------------------+
```

## 2. Start System

You have to run **`container system start`** to start the whole system.

`run()` first registers the XPC server `com.apple.container.apiserver` as a daemon managed by `launchd` [1], and it then fetches the VM init filesystem [2] and the Linux kernel image [3].

``` swift
// Sources/ContainerCommands/System/SystemStart.swift
extension Application {
    public struct SystemStart: AsyncLoggableCommand {
        public func run() async throws {
            // [...]
            let executablePath = try CommandLine.executablePath
                .removingLastComponent()
                .appending(FilePath.Component("container-apiserver"))
                .resolvingSymlinks()
            var args = [executablePath.string]
            args.append("start")
            // [...]
            let plist = LaunchPlist(
                label: "com.apple.container.apiserver",
                arguments: args,
                // [...]
                machServices: ["com.apple.container.apiserver"]
            )
            // [...]
            try ServiceManager.register(plistPath: plistURL.path) // [1]
            // [...]
            if await !initImageExists(containerSystemConfig: containerSystemConfig) {
                try? await installInitialFilesystem(initImage: containerSystemConfig.vminit.image) // [2]
            }
            try await installDefaultKernel(kernelURL: containerSystemConfig.kernel.url, kernelBinaryPath: containerSystemConfig.kernel.binaryPath) // [3]
        }

        private func installInitialFilesystem(initImage: String) async throws {
            var pullCommand = try ImagePull.parse()
            pullCommand.reference = initImage // initImage == "ghcr.io/apple/containerization/vminit:latest"
            log.info("Installing base container filesystem...")
            do {
                try await pullCommand.run()
            } catch {
                // [...]
            }
        }

        private func installDefaultKernel(kernelURL: URL, kernelBinaryPath: String) async throws {
            // [...]
            log.info("Installing kernel...")
            // kernelURL == "https://github.com/kata-containers/kata-containers/releases/download/3.28.0/kata-static-3.28.0-arm64.tar.zst"
            // kernelFilePath == "opt/kata/share/kata-containers/vmlinux-6.18.15-186"
            try await KernelSet.downloadAndInstallWithProgressBar(tarRemoteURL: kernelURL, kernelFilePath: kernelBinaryPath, force: true)
        }
    }
}
```

After that, the API server is running now, and we can talk to it in XPC.

## 3. Start container-apiserver XPC Server

`com.apple.container.apiserver` in Apple's container is like `dockerd` and `containerd` in the Docker system. Its XPC server is listening to handle container access requests.

When executing `container-apiserver start`, the `start` subcommand handler [1] is triggered to call `Start.run()`.

``` swift
// APIServer/APIServer.swift
struct APIServer: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "container-apiserver",
        // [...]
        subcommands: [Start.self], // [1]
    )
}
```

`run()` creates routing table [2], initializes all services, registers the XPC server `com.apple.container.apiserver` [3], and finally starts the server [4].

The functions with format `initializeXXX()` are to start service, including assigning endpoint handlers to harness handlers [5].

``` swift
// Sources/APIServer/APIServer+Start.swift
extension APIServer {
    struct Start: AsyncParsableCommand {
        func run() async throws {
            do {
                var routes = [XPCRoute: XPCServer.RouteHandler]() // [2]
                // [...]
                let containersService = try initializeContainersService(..., routes: &routes, ...)
                // [...]
                // call functions: initializeXXX(..., routes: &routes, ...) to bind handlers
                // [...]
                let server = XPCServer( // [3]
                    identifier: "com.apple.container.apiserver",
                    routes: routes.reduce(
                        into: [String: XPCServer.RouteHandler](),
                        {
                            $0[$1.key.rawValue] = $1.value
                        }), log: log)
                
                await withTaskGroup(of: Result<Void, Error>.self) { group in
                    group.addTask {
                        log.info("starting XPC server")
                        do {
                            try await server.listen() // [4]
                            return .success(())
                        } catch {
                            // [...]
                        }
                    }
                }
            } catch {
                // [...]
            }
        }

        private func initializeContainersService(
            routes: inout [XPCRoute: XPCServer.RouteHandler]
            // [...]
        ) throws -> ContainersService {
            let service = try ContainersService(
                // [...]
            )
            let harness = ContainersHarness(service: service, log: log)
            routes[XPCRoute.containerList] = XPCServer.route(harness.list) // [5]
            // [...]
            // call routes[XPCRoute.containerXXX] = XPCServer.route(harness.XXX) to fill the routes
            // [...]
        }
    }
}
```

`XPCServer`'s `handleMessage()` is called when receiving messages from clients. It checks if the EUIDs of server and client are the same [6]. If not, it rejects the request to ensure only the container daemon owner can send requests. Following that, it gets the route info from the XPC object [7] and calls the corresponding route handler [8].

``` swift
public struct XPCServer: Sendable {
    // [...]
    func handleMessage(connection: xpc_connection_t, object: xpc_object_t, session: XPCServerSession) async throws {
        // [...]
        // "server EUID == client EUID" is required
        var token = audit_token_t()
        xpc_dictionary_get_audit_token(object, &token)
        let serverEuid = geteuid()
        let clientEuid = audit_token_to_euid(token)
        guard clientEuid == serverEuid else { // [6]
            log.error(
                "unauthorized request - uid mismatch",
            )
            // [...]
        }
        // [...]
        guard let route = object.route else { /* ... */ } // [7]
        if let handler = routes[route] {
            do {
                let message = XPCMessage(object: object)
                let response = try await handler(message, session) // [8]
                xpc_connection_send_message(connection, response.underlying)
            } catch {
                // [...]
            }
        }
        // [...]
    }
}
```

The harness handler is responsible for decoding XPC message and forwarding the request to the service handler (`service.XXX`).

``` swift
// ContainerAPIService/Server/Containers/ContainersHarness.swift
public struct ContainersHarness: Sendable {
    let service: ContainersService
    // [...]
    public func bootstrap(_ message: XPCMessage) async throws -> XPCMessage {
        // the handler of harness.bootstrap
        // [...]
        try await service.bootstrap(id: id, stdio: stdio, dynamicEnv: env)
        // [...]
    }
    // [...]
}
```

The service handler is the actual one who handles the request.

``` swift
// Sources/Services/ContainerAPIService/Server/Containers/ContainersService.swift
public actor ContainersService {
    // [...]
    public func bootstrap(id: String, stdio: [FileHandle?], dynamicEnv: [String: String]) async throws {
        // [...]
    }
}
```

## 4. Start container-core-images XPC Server

There are multiple plugin configuration files (`config.toml`) in directories under `Sources/Plugins/`. These plugins are loaded during the apiserver initialization.

The plugin loader first filters plugins with `loadAtBoot=true` [1]. After that, these plugins are registered with `launchd` [2] and run as daemon processes.

``` swift
// Sources/APIServer/APIServer+Start.swift
extension APIServer {
    struct Start: AsyncParsableCommand {
        func run() async throws {
            do {
                // [...]
                let pluginLoader = try initializePluginLoader(log: log)
                try await initializePlugins(pluginLoader: pluginLoader, log: log, routes: &routes, debug: debug)
                // [...]
            } catch {
                // [...]
            }
        }

        private func initializePlugins(
            pluginLoader: PluginLoader,
            log: Logger,
            routes: inout [XPCRoute: XPCServer.RouteHandler],
            debug: Bool = false
        ) async throws {
            // [...]
            let bootPlugins = pluginLoader.findPlugins().filter { $0.shouldBoot } // [1]
            let service = PluginsService(pluginLoader: pluginLoader, log: log)
            try await service.loadAll(bootPlugins, debug: debug)
            // [...]
        }
    }
}

// Sources/Services/ContainerAPIService/Server/Plugin/PluginsService.swift
public actor PluginsService {
    // [...]
    public func loadAll(
        _ plugins: [Plugin]? = nil,
        debug: Bool = false
    ) throws {
        let registerPlugins = plugins ?? pluginLoader.findPlugins()
        for plugin in registerPlugins {
            try pluginLoader.registerWithLaunchd(plugin: plugin, debug: debug) // [2]
            loaded[plugin.name] = plugin
        }
    }
    // [...]
}
```

One of the loaded plugins is the image management plugin (`Sources/Plugins/CoreImages/config.toml`), and its helper binary (`container-core-images`) registers an XPC server, which provides image-related operations [3].

``` swift
// Sources/Plugins/CoreImages/ImagesHelper.swift
struct ImagesHelper: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "container-core-images",
        // [...]
    )
}

extension ImagesHelper {
    struct Start: AsyncParsableCommand {
        private func initializeImagesService(root: FilePath, containerSystemConfig: ContainerSystemConfig, log: Logger, routes: inout [String: XPCServer.RouteHandler]) throws {
            // [...]
            routes[ImagesServiceXPCRoute.imagePull.rawValue] = XPCServer.route(harness.pull) // [3]
            // [...]
        }
    }
}
```

## 5. Create Container

The container service is registered in the XPC server `com.apple.container.apiserver`, and its `create` endpoint can set up a container execution environment.

It first gets the filesystem used by the VM kernel [1], which is the init filesystem (`ghcr.io/apple/containerization/vminit:<tag>`) we fetched before. Then it pulls the image of the container, creating the container's rootfs [2]. A `RuntimeConfiguration` object is later created [3] to save all the settings to a config file. Finally, the container state is updated to `.stopped` [4].

Fun fact, if you trace the call flow, you may find that the VM kernel image and the image of the container are both pulled by the same function - `getCreateSnapshot()`.

``` swift
// Sources/Services/ContainerAPIService/Server/Containers/ContainersService.swift
public actor ContainersService {
    // [...]
    public func create(configuration: ContainerConfiguration, kernel: Kernel, options: ContainerCreateOptions, initImage: String? = nil, runtimeData: Data? = nil) async throws {
        // [...]
        try await /* ... */ {
            let initFilesystem = try await self.getInitBlock(for: systemPlatform.ociPlatform(), imageRef: initImage) // [1]
            do {
                let containerImage = ClientImage(description: configuration.image)
                let imageFs = try await options.rootFsOverride == nil ? containerImage.getCreateSnapshot(platform: configuration.platform) : nil // [2]

                let runtimeConfig = RuntimeConfiguration( // [3]
                    path: path,
                    initialFilesystem: initFilesystem,
                    kernel: kernel,
                    containerConfiguration: configuration,
                    containerRootFilesystem: imageFs,
                    options: options,
                    runtimeData: runtimeData
                )
                try runtimeConfig.writeRuntimeConfiguration()

                let snapshot = ContainerSnapshot(
                    configuration: configuration,
                    status: .stopped,
                    networks: [],
                    startedDate: nil
                )
                await self.setContainerState(configuration.id, ContainerState(snapshot: snapshot), context: context) // [4]
            } catch {
                // [...]
            }
        }
    }

    // [...]
    private func getInitBlock(for platform: Platform, imageRef: String? = nil) async throws -> Filesystem {
        let ref = imageRef ?? containerSystemConfig.vminit.image
        let initImage = try await ClientImage.fetch(reference: ref, platform: platform, containerSystemConfig: containerSystemConfig)
        var fs = try await initImage.getCreateSnapshot(platform: platform) // <-------------
        fs.options = ["ro"]
        return fs
    }
}
```

`ClientImage` is a client side interface of the XPC server `container-core-images`. `getCreateSnapshot()` first sends `snapshotGet` request to get the snapshot [5]. If not found, it then sends another `imageUnpack` request [6] to create one.

``` swift
// Sources/Services/ContainerAPIService/Client/ClientImage.swift
extension ClientImage {
    private static let serviceIdentifier = "com.apple.container.core.container-core-images"

    private static func newXPCClient() -> XPCClient {
        XPCClient(service: Self.serviceIdentifier)
    }
    // [...]
}

extension ClientImage {
    // [...]
    public func unpack(platform: Platform?, progressUpdate: ProgressUpdateHandler? = nil) async throws {
        let client = Self.newXPCClient()
        let request = Self.newRequest(.imageUnpack)
        // [...]
        try await client.send(request)
        // [...]
    }

    // [...]
    public func getSnapshot(platform: Platform) async throws -> Filesystem {
        let client = Self.newXPCClient()
        let request = Self.newRequest(.snapshotGet)
        // [...]
        let response = try await client.send(request)
        // [...]
    }

    public func getCreateSnapshot(platform: Platform, progressUpdate: ProgressUpdateHandler? = nil) async throws -> Filesystem {
        do {
            // get
            return try await self.getSnapshot(platform: platform) // [5]
        } catch let err as ContainerizationError {
            // [...]
            // not found -> create
            try await self.unpack(platform: platform, progressUpdate: progressUpdate) // [6]
            return try await self.getSnapshot(platform: platform)
        }
    }
}
```

Once `container-core-images` receives the request, it calls `ImagesService`'s `unpack()` to get image from ImageStore [7], and then it converts the image to snapshot via SnapshotStore [8].

``` swift
// Sources/Services/ContainerImagesService/Server/ImagesService.swift
public actor ImagesService {
    // [...]
    private let contentStore: ContentStore
    private let imageStore: ImageStore
    private let snapshotStore: SnapshotStore
    // [...]
    private func _get(_ reference: String) async throws -> Containerization.Image {
        try await imageStore.get(reference: reference)
    }
    // [...]
}
extension ImagesService {
    public func unpack(description: ImageDescription, platform: Platform?, progressUpdate: ProgressUpdateHandler?) async throws {
        let img = try await self._get(description) // [7]
        try await self.snapshotStore.unpack(image: img, platform: platform, progressUpdate: progressUpdate) // [8]
    }
}
```

Here we simply explain the functions of three different stores:
1. **ContentStore**: saves **raw data**, including manifest, config (JSON) and blob (tar). Identifies them by digest.
2. **ImageStore**: saves image metadata, such as the mapping between reference (image name + tag, like "ubuntu:24.04") and root digest.
3. **SnapshotStore**: saves unpacked data into a filesystem image or a directory containing all files. It should be able to be directly mounted.

These three stores are implemented in another project: **[Containerization](https://github.com/apple/containerization)**.

ImageStore first finds images from the filesystem [5]. If not found, it calls `pull()` to download the target image from remote [6].

``` swift
// Sources/Containerization/Image/ImageStore/ImageStore.swift
extension ImageStore {
    public func get(reference: String, pull: Bool = false) async throws -> Image {
        do {
            let desc = try await self.referenceManager.get(reference: reference) // [5]
            return Image(description: desc, contentStore: self.contentStore)
        } catch /* ... */ {
            if error.code == .notFound && pull {
                return try await self.pull(reference: reference) // [6]
            }
            // [...]
        }
    }
}
```

`pull()` downloads manifests, configs and layers, and it then saves them into ContentStore. Later, the association of the image and these files is registered in ImageStore.

Now the image has been downloaded, and we go back to see how `unpack()` handles them to a snapshot.

For images supporting multi-arch, each arch corresponds to a **manifest Descriptor**. If specifying a platform like `amd64`, `unpack()` only takes the image desc of the target platform [7]. It then calls the unpacker's `unpack()` handler [8] to parse the desc, overlaying layers referred to by the image desc into an EXT4 image and returning `mount`. `mount` contains mounting information like the image type and the options, and this information is finally saved into the snapshot info [9].

During the whole process, the snapshot (EXT4 image) and the snapshot info (JSON file) are all saved into a temporary directory first. Once the unpacking process has been done, they are moved from the temp dir to the target snapshot dir [10] in the end.

``` swift
// Sources/Services/ContainerImagesService/Server/SnapshotStore.swift
public actor SnapshotStore {
    public func unpack(image: Containerization.Image, platform: Platform? = nil, progressUpdate: ProgressUpdateHandler?) async throws {
        // [...]
        let desc = try await image.descriptor(for: platform) // [7]
        toUnpack = [desc]
        // [...]
        for desc in toUnpack {
            let snapshotDir = self.snapshotDir(desc) // <root>/<digest>
            let unpacker = try await self.unpackStrategy(image, platform) // by default it is EXT4Unpacker()

            do {
                // [...]
                let mount = try await unpacker.unpack(image, for: platform, at: tempSnapshotPath, progress: progress) // [8]
                let fs = Filesystem.block(
                    format: mount.type,
                    source: self.snapshotPath(desc).absolutePath(),
                    destination: mount.destination,
                    options: mount.options
                )
                let snapshotInfo = try JSONEncoder().encode(fs)
                self.fm.createFile(atPath: infoPath.absolutePath(), contents: snapshotInfo) // [9]
            } catch {
                // [...]
            }

            do {
                try fm.moveItem(at: tempDir, to: snapshotDir) // [10]
            } catch {
                // [...]
            }
        }
    }
}
```

Unlike `containerd` in Linux, Apple container generates an **EXT4 image** as the container's snapshot. I think it is because `containerd` is running on native Linux, and it is pretty easy and cheap to mount a directory to a container. However, Apple container is running inside a separate VM, so **exposing the image to the VM as a device** then **mounting it** is the best way to set up a container.

## 6. Start Container (only kernel init process)

After the VM environment and filesystems have been set up, endpoint `bootstrap` is used to start the VM.

Container service's `bootstrap()` is called to register a `container-runtime-linux` daemon with `launchd` [1]. It acts as a container shim, controlling the container lifecycle. Here `id` is the booting container ID. Then it creates a runtime client [2] to talk to `container-runtime-linux` and calls runtime service's `bootstrap()` [3].

``` swift
// Sources/Services/ContainerAPIService/Server/Containers/ContainersService.swift
public actor ContainersService {
    // [...]
    public func bootstrap(id: String, stdio: [FileHandle?], dynamicEnv: [String: String]) async throws {
        // [...]
        try await /* ... */ {
            // [...]
            let path = self.containerRoot.appendingPathComponent(id)
            let (config, _) = try Self.getContainerConfiguration(at: path)
            // [...]
            do {
                try Self.registerService( // [1]
                    // [...]
                )
                // [...]
                let runtime = state.snapshot.configuration.runtimeHandler // "container-runtime-linux"
                let runtimeClient = try await RuntimeClient.create( // [2]
                    id: id,
                    runtime: runtime
                )
                try await runtimeClient.bootstrap(stdio: stdio, networkBootstrapInfos: networkBootstrapInfos, dynamicEnv: dynamicEnv) // [3]
            }
        }
    }
}
```

Actually, the `container-runtime-linux` daemon runs two XPC servers: the **endpoint server** and the **main server**. The main server is the main service providing container control operations, including bootstrap [4], but it is created as an anonymous connection [5] by design, which means that no one can connect to it.

To access the main server, you have to call the endpoint `createEndpoint` of the endpoint server, which is also its only method [6].

``` swift
// Sources/Plugins/RuntimeLinux/RuntimeLinuxHelper+Start.swift
extension RuntimeLinuxHelper {
    struct Start: AsyncParsableCommand {
        func run() async throws {
            do {
                // [...]
                let anonymousConnection = xpc_connection_create(nil, nil)
                let server = RuntimeService(
                    // [...]
                    connection: anonymousConnection,
                )

                // [...]
                let endpointServer = XPCServer(
                    identifier: machServiceLabel,
                    routes: [
                        RuntimeRoutes.createEndpoint.rawValue: XPCServer.route(server.createEndpoint) // [6]
                    ],
                    log: log
                )
                // [...]
                let mainServer = XPCServer(
                    connection: anonymousConnection, // [5]
                    routes: [
                        // [...]
                        RuntimeRoutes.bootstrap.rawValue: XPCServer.route(server.bootstrap), // [4]
                        // [...]
                    ],
                    log: log
                )
                // [...]
            } catch {
                // [...]
            }
        }
    }
}
```

`createEndpoint()` handler replies the request with a main server connection [7] so that the client can talk to the main server.

``` swift
// Sources/Services/RuntimeLinux/Server/RuntimeService.swift
public actor RuntimeService {
    // [...]
    public func createEndpoint(_ message: XPCMessage) async throws -> XPCMessage {
        let endpoint = xpc_endpoint_create(self.connection) // [7]
        let reply = message.reply()
        reply.set(key: RuntimeKeys.runtimeServiceEndpoint.rawValue, value: endpoint)
        return reply
    }
    // [...]
}
```

Going back to see runtime service's `bootstrap()`, it handles the VM execution initialization, such as kernel boot parameters [8]. It finally calls `container.create()` to create a container [9].

``` swift
// Services/RuntimeLinux/Server/RuntimeService.swift
public actor RuntimeService {
    // [...]
    public func bootstrap(_ message: XPCMessage) async throws -> XPCMessage {
        // [...]
        return try await /* ... */ {
            var kernel = try bundle.kernel
            kernel.commandLine.kernelArgs.append("oops=panic") // [8]
            kernel.commandLine.kernelArgs.append("lsm=lockdown,capability,landlock,yama,apparmor")
            let vmm = VZVirtualMachineManager(
                kernel: kernel,
                initialFilesystem: bundle.initialFilesystem.asMount,
                // [...]
            )
            // [...]
            let container = try LinuxContainer(id, rootfs: rootfs, vmm: vmm, logger: self.log) {
                // [...]
            }
            // [...]
            do {
                try await container.create() // [9]
                // [...]
                await self.setState(.booted)
            } catch {
                // [...]
            }
        }
    }
}
```

The container VM-related operations are also defined in [Containerization](https://github.com/apple/containerization).

`create()` is responsible for creating and booting the micro-VM, and preparing the container environment (rootfs, network, mounting). It first calls VMM's `create` handler [10] to create a VM instance and then calls the VM's `start` handler [11] to boot the VM. Internally, the `start` handler of the `VZVirtualMachine` structure is called, but we cannot trace further because `self.start` is implemented in **Apple Virtualization.framework** [12].

After booting the VM, it connects to the VM's init process `vminitd` via **vsock** [13], and it then asks `vminitd` to initialize the VM runtime, such as mounting the VirtIO interface [14] and mounting the container's rootfs [15].

``` swift
// Sources/Containerization/LinuxContainer.swift
extension LinuxContainer {
    public func create() async throws {
        try await /* ... */ {
            let vm = try await self.vmm.create(config: creationConfig) // [10]
            try await vm.start() // [11]
            do {
                try await vm.withAgent { agent in
                    // [...]
                    try await agent.mount(
                        ContainerizationOCI.Mount( // [14]
                            type: "virtiofs",
                            source: "virtiofs",
                            destination: "/run/virtiofs",
                            options: []
                        ))
                    // [...]
                }
                // [...]

                try await self.mountRootfs(attachments: attachments, rootfsPath: rootfsPath, agent: agent) // [15]
                // [...]
            }
        }
    }
}

// Sources/Containerization/VZVirtualMachineManager.swift
public struct VZVirtualMachineManager: VirtualMachineManager {
    // [...]
    public func create(config: some VMCreationConfig) throws -> any VirtualMachineInstance {
        // [...]
        return try VZVirtualMachineInstance(
            // [...]
            )
    }
}

// Sources/Containerization/VZVirtualMachineInstance.swift
public final class VZVirtualMachineInstance: Sendable {
    // [...]
    init(group: EventLoopGroup?, config: Configuration, logger: Logger?) throws {
        self.vm = VZVirtualMachine(
            configuration: try config.toVZ(allocator: allocator),
            queue: self.queue
        )
    }
}

extension VZVirtualMachineInstance: VirtualMachineInstance {
    public func start() async throws {
        try await lock.withLock { _ in
            // [...]
            try await self.vm.start(queue: self.queue) // <-------------
            // [...]
            let agent = try Vminitd( // [13]
                connection: try await self.vm.waitForAgent(queue: self.queue),
                group: self.group
            )
            // [...]
        }
    }
}

// Sources/Containerization/VZVirtualMachine+Helpers.swift
extension VZVirtualMachine {
    // [...]
    func start(queue: DispatchQueue) async throws {
        try await /* ... */ { /* ... */ in
            queue.sync {
                self.start { result in // [12]
                    // [...]
                    cont.resume()
                }
            }
        }
    }
    // [...]
}
```

`VZVirtualMachine` is defined in the SDK libraries [13].

``` c
// /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/System/Library/Frameworks/Virtualization.framework/Versions/A/Headers/VZVirtualMachine.h
// [...]
/*!
@abstract VZVirtualMachine represents the entire state of a single virtual machine.
@discussion
   A Virtual Machine is the emulation of a complete hardware machine of the same architecture as the real hardware machine.
   When executing the Virtual Machine, the Virtualization framework uses certain hardware resources and emulates others to provide
   and great performance.
   The definition of a virtual machine starts with its configuration. This is done by setting up a VZVirtualMachineConfiguration o
   Once configured, the virtual machine can be started with [VZVirtualMachine startWithCompletionHandler:].
   To install macOS on a virtual machine, configure a new virtual machine with a suitable VZMacPlatformConfiguration, then use a V
   to install the restore image on it.
   Creating a virtual machine using the Virtualization framework requires the app to have the "com.apple.security.virtualization"
@seealso VZVirtualMachineConfiguration
@seealso VZMacOSInstaller
*/
VZ_EXPORT API_AVAILABLE(macos(11.0))
@interface VZVirtualMachine : NSObject // [13]
// [...]
```

The Apple hypervisor is an in-process framework, which internally uses hardware virtualization, so it won't spawn other processes. As a result, `container-runtime-linux` is the process that both controls the VM and runs the VM. (btw iOS doesn't support the Virtualization Framework)

## 7. Cross-arch VM / Container

Apple container is based on hardware virtualization but still supports cross-arch VM, how?

The magic is that when creating a VM instance, it exposes the `rosetta` binary with the tag `"rosetta"` to the VM [1].

``` swift
// Sources/Containerization/VZVirtualMachineInstance.swift
public final class VZVirtualMachineInstance: Sendable {
    init(group: EventLoopGroup?, config: Configuration, logger: Logger?) throws {
        // [...]
        self.vm = VZVirtualMachine(
            configuration: try config.toVZ(allocator: allocator), // <-------------
            queue: self.queue
        )
        // [...]
    }
}

extension VZVirtualMachineInstance.Configuration {
    func toVZ(allocator: any AddressAllocator<Character>) throws -> VZVirtualMachineConfiguration {
        if self.rosetta {
            case .installed:
                let share = try VZLinuxRosettaDirectoryShare() // virtualization framework API
                let device = VZVirtioFileSystemDeviceConfiguration(tag: "rosetta") // [1]
                device.share = share
                config.directorySharingDevices.append(device)
        }
    }
}
```

During booting, `rosetta` is mounted into the VM [2] and registered as the x86_64 binary loader via `binfmt_misc` [3].

``` swift
// Sources/Containerization/Vminitd+Rosetta.swift
extension Vminitd {
    /// Enable Rosetta's x86_64 emulation.
    public func enableRosetta() async throws {
        let path = "/run/rosetta"
        try await self.mount(
            .init(
                type: "virtiofs",
                source: "rosetta", // [2]
                destination: path
            )
        )
        try await self.setupEmulator( // [3]
            binaryPath: "\(path)/rosetta",
            configuration: Binfmt.Entry.amd64()
        )
    }
}
```

So `rosetta` automatically runs as the loader when an x86_64 binary is executed in the arm64 VM.

``` bash
root@df733a90-6be1-4fda-bc8b-89ed1be716dd:/# ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  1.4  0.6 166188  7132 pts/0    Ss   06:06   0:00 /run/rosetta/rosetta /usr/bin/bash
root           4  100  0.5 167876  6180 pts/0    R+   06:06   0:00 /run/rosetta/rosetta /usr/bin/ps aux
```

## 8. Run process in Container

The first process of the container (entrypoint) is run by the `startProcess` endpoint. The container service forwards the request to the `container-runtime-linux` XPC server [1].

``` swift
// Sources/Services/ContainerAPIService/Server/Containers/ContainersService.swift
public actor ContainersService {
    // [...]
    public func startProcess(id: String, processID: String) async throws {
        // [...]
        try await /* ... */ {
            let client = try state.getClient()
            try await client.startProcess(processID) // [1]
        }
    }
    // [...]
}
```

Runtime service's `startProcess()` internally calls container's `start` handler [2].

``` swift
// Sources/Services/RuntimeLinux/Server/RuntimeService.swift
public actor RuntimeService {
    @Sendable
    public func startProcess(_ message: XPCMessage) async throws -> XPCMessage {
        // [...]
        return try await /* ... */ { lock in
            let id = try message.id()
            let containerInfo = try await self.getContainer()
            let containerId = containerInfo.container.id
            if id == containerId {
                try await self.startInitProcess(lock: lock) // <-------------
                await self.setState(.running)
            } else {
                // [...]
            }
            return message.reply()
        }
    }
    // [...]
    private func startInitProcess(lock: AsyncLock.Context) async throws {
        let info = try self.getContainer()
        let container = info.container
        // [...]
        do {
            // [...]
            try await container.start() // [2]
            // [...]
        }
    }
}
```

Container's `start()` generates an OCI spec and initializes it. Eventually, it executes the OCI runtime binary [3] inside the VM and starts the container based on the OCI spec.

``` swift
// Sources/Containerization/LinuxContainer.swift
extension LinuxContainer {
    public func start() async throws {
        try await /* ... */ { state in
            var spec = self.generateRuntimeSpec()
            // [...]
            // initialize OCI spec
            // [...]
            let agent = try await createdState.vm.dialAgent()
            do {
                let process = LinuxProcess(
                    // [...]
                    ociRuntimePath: self.config.ociRuntimePath, // "nil" by default
                    // [...]
                )
                try await process.start() // [3]
            } catch {
                // [...]
            }
        }
    }
}
```

When the VM's `vminitd` receives a `createProcess` request, it first decodes the message and gets the OCI spec [4]. Following that, it creates a `ManagedContainer` object [5] to manage that container.

``` swift
// vminitd/Sources/VminitdCore/Server+GRPC.swift
extension Initd: Com_Apple_Containerization_Sandbox_V3_SandboxContext.SimpleServiceProtocol {
    public func createProcess(
        request: Com_Apple_Containerization_Sandbox_V3_CreateProcessRequest, context: GRPCCore.ServerContext
    ) async throws -> Com_Apple_Containerization_Sandbox_V3_CreateProcessResponse {
        do {
            var ociSpec = try JSONDecoder().decode( // [4]
                // [...]
                from: request.configuration
            )

            // [...]
            else { // new container
                // [...]
                let ctr = try await ManagedContainer( // [5]
                    id: request.id,
                    stdio: stdioPorts,
                    spec: ociSpec,
                    ociRuntimePath: request.hasOciRuntimePath ? request.ociRuntimePath : nil,
                    log: self.log
                )
                // [...]
            }
        }
    }
}
```

If the runtime is not specified, `vminitd` will use the `"vmexec"` binary as the runtime loader [6]. The `bundle` here [7] is the directory which contains the container's rootfs and the OCI spec (`config.json`).

``` swift
// vminitd/Sources/VminitdCore/ManagedContainer.swift
public actor ManagedContainer {
    init(
        id: String,
        stdio: HostStdio,
        spec: ContainerizationOCI.Spec,
        ociRuntimePath: String? = nil,
        log: Logger
    ) async throws {
        // [...]
        let bundle = try ContainerizationOCI.Bundle.create(
            path: Self.craftBundlePath(id: id),
            spec: spec
        )
        // [...]
        do {
            if let runtimePath = ociRuntimePath {
                // [...]
            } else {
                // Use vmexec runtime
                initProcess = try ManagedProcess( // <-------------
                    id: id,
                    stdio: stdio,
                    bundle: bundle, // [7]
                    // [...]
                )
                // [...]
            }
        } catch {
            // [...]
        }
    }
}

// vminitd/Sources/VminitdCore/ManagedProcess.swift
final class ManagedProcess: ContainerProcess, Sendable {
    init(
        bundle: ContainerizationOCI.Bundle,
    ) {
        // [...]
        else {
            args = ["run", "--bundle-path", bundle.path.path]
        }

        var command = Command(
            "/sbin/vmexec", // [6]
            arguments: args,
            // [...]
        )
        // [...]
        try io.start(process: &command)
        // [...]
    }
}
```

The container's rootfs is the EXT4 image. The image is mounted into the VM by `mountRootfs()` during container creation [7] with the destination path format `/run/container/<container_id>/rootfs`.

``` swift
// Sources/Containerization/LinuxContainer.swift
extension LinuxContainer {
    // called by LinuxContainer.create()
    private func mountRootfs(
        attachments: [AttachedFilesystem],
        rootfsPath: String,
        agent: VirtualMachineAgent
    ) async throws {
        let rootfsAttachment = attachments.first
        // [...]
        if self.writableLayer != nil {
            // [...]
            // mount with overlayfs
        } else {
            // No writable layer. Mount rootfs directly.
            var rootfs = rootfsAttachment.to
            rootfs.destination = rootfsPath
            try await agent.mount(rootfs) // [7]
        }
    }
}
```

Finally, when the runtime is executed (`vmexec run --bundle ...`), `childRootSetup()` is called internally to mount the rootfs as the container's rootfs [8]. `rootfs.path` here is that mounted EXT4 image.

``` swift
// vminitd/Sources/vmexec/RunCommand.swift
struct RunCommand: ParsableCommand {
    mutating func run() throws {
        do {
            let spec: ContainerizationOCI.Spec
            do {
                let bundle = try ContainerizationOCI.Bundle.load(path: URL(filePath: bundlePath))
                spec = try bundle.loadConfig()
            } catch {
                // [...]
            }
            try execInNamespace(spec: spec) // <-------------
        } catch {
            // [...]
        }
    }

    private func childRootSetup(rootfs: ContainerizationOCI.Root, mounts: [ContainerizationOCI.Mount]) throws { // [8]
        // setup rootfs
        try prepareRoot(rootfs: rootfs.path)
        try mountRootfs(rootfs: rootfs.path, mounts: mounts)
        // [...]
        try pivotRoot(rootfs: rootfs.path)
        // [...]
    }

    private func childSetup(
        spec: ContainerizationOCI.Spec,
        ackPipe: FileDescriptor,
        syncPipe: FileDescriptor
    ) throws {
        // [...]
        try childRootSetup(rootfs: root, mounts: spec.mounts) // <-------------
        // [...]
    }

    private func execInNamespace(spec: ContainerizationOCI.Spec) throws {
        // [...]
        unshare(unshareFlags)
        // [...]
        let processID = fork()
        if processID == 0 {  // child
            try childSetup(spec: spec, ackPipe: ackPipe, syncPipe: syncPipe) // <-------------
        } else {
            // [...]
        }
    }
}
```

## 9. Attack Surfaces

### 9.1. Pulling Image

Could unpacking a tar to an EXT4 image lead to any problems?

The EXT4 unpacker uses an `ArchiveReader` object to read the layer blob [1] and forwards the request to the EXT4 formatter [2].

``` swift
// Sources/Containerization/Image/Unpacker/EXT4Unpacker.swift
public struct EXT4Unpacker: Unpacker {
    // [...]
    public func unpack(
        _ image: Image,
        for platform: Platform,
        at path: URL,
        progress: ProgressHandler? = nil
    ) async throws -> Mount {
        // [...]
        for resolved in resolvedLayers {
            // [...]
            let reader = try ArchiveReader( // [1]
                format: .paxRestricted,
                filter: resolved.filter,
                file: resolved.file
            )
            try await filesystem.unpack(reader: reader, progress: progress) // [2]
        }
        // [...]
    }
    // [...]
}
```

`unpackEntries()` is the key function that does the tar-to-ext4 logic. You may find some file operations inside the function [3], but they all **operate on an in-memory filesystem**, which means these operations **do not access the host filesystem**.

``` swift
// Sources/ContainerizationEXT4/Formatter+Unpack.swift
extension EXT4.Formatter {
    /// Unpack the provided archive on to the ext4 filesystem.
    public func unpack(reader: ArchiveReader, progress: ProgressHandler? = nil) async throws {
        try await self.unpackEntries(reader: reader, progress: progress) // <-------------
    }

    private func unpackEntries(reader: ArchiveReader, progress: ProgressHandler?) async throws {
        for (entry, streamReader) in reader.makeStreamingIterator() {
            // [...]
            if path.base.hasPrefix(".wh.") {
                // [...]
                try self.unlink(path: dir.join(filePath)) // [3]
                // [...]
            }
        }
    }
}
```

As a result, tar path-traversal cannot escape to the host during unpack.

### 9.2. Guest-To-Host

When the host tries to copy data from the guest VM, `copyOut()` is called. If it finds the data is an archived file [1], it loads the data via `ArchiveReader` [2] and extracts it to the host filesystem [3].

``` swift
public final class LinuxContainer: Container, Sendable {
    public func copyOut(
        from source: URL,
        to destination: URL,
        createParents: Bool = true,
        chunkSize: Int = defaultCopyChunkSize
    ) async throws {
        try await /* ... */ {
            let guestPath = URL(filePath: self.root).appending(path: source.path)
            try await withThrowingTaskGroup(of: Void.self) { group in
            // [...]
                group.addTask {
                    guard let metadata = await metadataStream.first(where: { _ in true }) else {
                        // [...]
                    }
                    // [...]

                    try await /* ... */ in
                        self.copyQueue.async {
                            do {
                                // [...]
                                if metadata.isArchive { // [1]
                                    try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
                                    let fh = FileHandle(fileDescriptor: dup(conn.fileDescriptor), closeOnDealloc: true)
                                    let reader = try ArchiveReader(format: .pax, filter: .gzip, fileHandle: fh) // [2]
                                    _ = try reader.extractContents(to: destination) // [3]
                                }
                            }
                        }
                }
            }
        }
    }
}
```

However, `ArchiveReader` is hardened with an anti-symlink check (`O_NOFOLLOW`) [4] and has been tested against many edge cases. For example, you can see that `rejectPathTraversal()` tests crafted tar entries [5] whose names are path-traversal payloads.

``` swift
// Sources/ContainerizationArchive/ArchiveReader.swift
extension ArchiveReader {
    // [...]
    private func extractEntry(
        entry: WriteEntry,
        dataReader: ArchiveEntryReader,
        memberPath: FilePath,
        rootFileDescriptor: FileDescriptor
    ) throws -> Bool {
        do {
            switch type {
            case .regular:
                // mkdir also has O_NOFOLLOW
                try FileDescriptorOps.mkdir(rootFileDescriptor, relativePath, makeIntermediates: true) { fd in
                    // [...]
                    let fileFd = openat(fd.rawValue, lastComponent.string, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, fileMode) // [4]
                }
            }
        }
    }
}
// Tests/ContainerizationArchiveTests/ArchiveReaderTests.swift
struct ArchiveReaderTests {
    @Test func rejectPathTraversal() throws {
        let archiveURL = try createTestArchive(
            name: "evil-traversal",
            entries: [ // [5]
                ("../etc/pwned", .regular("evil"), nil),
                ("foo/../../etc/pwned", .regular("evil"), nil),
                ("dir/../../../etc/pwned", .regular("evil"), nil),
            ])
        // [...]
    }
}
```

## 10. Summary

This post analyzes how Apple container works. We covered the whole process from CLI, apiserver, runtime-linux, VM, vminitd, to vmexec, ending at the container's first process. We also discussed a little bit about its attack surfaces. From my perspective, its design is quite robust thanks to extensive malformed-payload testing and running each container in an isolated VM; meanwhile, it still has good performance thanks to hardware virtualization.