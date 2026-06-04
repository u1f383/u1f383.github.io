---
layout: post
title:  "Docker Internal (1)"
categories: Linux
---

For this year's (2026) Pwn2Own Berlin, I tried to find vulnerabilities in Docker but came up with nothing. This post simply documents my research on Docker's system implementation, since it is quite interesting.

The attack scenario involves downloading an unknown image or running a malicious image, so I only focus on its architecture and then delve into the code that accesses user-controllable data.

This series is expected to be divided into three parts, covering basic Docker's architecture, attack surfaces, past vulnerabilities, and the NVIDIA toolkit as a bonus! I hope you enjoy these posts and learn something new 🙂.

## 1. Introduction

First, there are a few Docker products that may confuse readers. The most common one is [Docker Engine](https://docs.docker.com/engine/install/ubuntu/), and another is [Docker Desktop](https://www.docker.com/products/docker-desktop/), which is relatively niche but more user-friendly since it provides a GUI and runs containers inside a **lightweight VM** (for example, QEMU-KVM). Here, we are discussing **Docker Engine**, not the Docker Desktop.

If you follow the installation steps for Docker Engine on Ubuntu, you'll notice that `containerd` is installed as well!

``` bash
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
                                         ^^^^^^^^^^^^^
```

In fact, the Docker Engine consists of several components: the CLI tool (`docker-cli`), the frontend (`dockerd`), the backend (`containerd`), the container's shim daemon (`containerd-shim-runc-v2`) and loader (`runc`). The interaction between each components looks like this:

<img src="/assets/image-20260526000000001.png" alt="image-20260526000000001" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

When executing a command like `docker run -it ubuntu /bin/bash`, `docker-cli` first connects to the Unix socket `docker.sock` and sends the request. Then, `dockerd` wraps the request in gRPC format and forwards it to `containerd` via the Unix socket `containerd.sock`. `containerd` is responsible for loading the image, invoking `runc` to create a container, and managing the container lifecycle. Finally, the container is spawned in an isolated execution environment based on Linux namespace, capabilities and cgroups.

As the backend of Docker Engine, or precisely **the container runtime**, `containerd` can also be used by other engines or orchestrators, such as Kubernetes.

By the way, according to the Pwn2Own rules, Docker Engine and `containerd` are listed as two separate targets, but since Docker Engine appears to depend on `containerd` as its backend and cannot run on its own, I'm not sure what the attack scenarios for each would be.

Anyway, let's first take a look at how the `dockerd` handles HTTP requests and sends gRPC requests to `containerd`!

## 2. dockerd

The source code for both `docker-cli` and `dockerd` can be found in the [moby/moby GitHub repo](https://github.com/moby/moby).

### 2.1. Register API Endpoints

The entry point of the Docker daemon (`dockerd`) is `start()` in `daemon/command/daemon.go`. `start()` creates an HTTP server [1] that supports both the **gRPC protocol** [2] and the **HTTP protocol** [3], since other CLI tools may communicate via gRPC.

``` go
// daemon/command/daemon.go
func (cli *daemonCLI) start(ctx context.Context) (retErr error) {
    // [...]
    httpServer := &http.Server{
        // [...]
    }
    // [...]
    var p http.Protocols
    p.SetHTTP1(true)
    p.SetHTTP2(true)
    p.SetUnencryptedHTTP2(true)

    routers := buildRouters(routerOptions{
        features: d.Features,
        daemon:   d,
        cluster:  c,
        builder:  b,
    })
    gs := newGRPCServer(ctx)
    b.backend.RegisterGRPC(gs) // [2]
    httpServer.Protocols = &p // [3]
    httpServer.Handler = newHTTPHandler(ctx, gs, apiServer.CreateMux(ctx, routers...)) // [1]
    // [...]
    httpServer.Serve(ls)
    // [...]
}

// daemon/command/httphandler.go
func newHTTPHandler(ctx context.Context, gs *grpc.Server, apiServer http.Handler) http.Handler {
    return &httpHandler{
        ctx:        ctx,
        grpcServer: gs,
        apiServer:  apiServer,
    }
}
```

`httpServer` is an `http.Server` object from Go's `net/http` package, and the `ServeHTTP()` method of its `.Handler` field is called whenever a request arrives. It handles requests in two different ways: if the Content-Type in the HTTP request header is gRPC, the request is dispatched to gRPC server [4]; otherwise, the HTTP server treats it as a REST HTTP request and handle it accordingly [5].

``` go
// daemon/command/httphandler.go
func (h *httpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
        h.grpcServer.ServeHTTP(w, r) // [4]
    } else {
        h.apiServer.ServeHTTP(w, r) // [5]
    }
}
```

`buildRouters()` calls the `.NewRouter()` function of several packages to set up routing. Take the `container` package [6] as an example: its `initRoutes()` [7] function is called internally and defines the endpoints along with their handlers.

``` go
// daemon/command/daemon.go
import (
    // [...]
    "github.com/moby/moby/v2/daemon/server/router/container"
    // [...]
)

func buildRouters(opts routerOptions) []router.Router {
    routers := []router.Router{
        // [...]
        container.NewRouter(opts.daemon), // [6]
        // [...]
    }
}

// daemon/server/router/container/container.go
func NewRouter(b Backend) router.Router {
    r := &containerRouter{
        backend: b,
    }
    r.initRoutes() // [7]
    return r
}

func (c *containerRouter) initRoutes() {
    c.routes = []router.Route{
        // [...]
        router.NewPostRoute("/containers/{name:.*}/pause", c.postContainersPause),
        // [...]
    }
}
```

### 2.2. Send Request to containerd

Some endpoints simply return status or metadata, but others handle more complex tasks and need to forward requests to `containerd`. Here, we'll use **pausing a container** as an example (since it's more straightforward).

Pausing a container is handled by `postContainersPause()` [1], which internally calls `t.Task.Pause()` [2].

``` go
// daemon/server/router/container/container.go
func (c *containerRouter) initRoutes() {
    c.routes = []router.Route{
        // [...]
        router.NewPostRoute("/containers/{name:.*}/pause", c.postContainersPause), // [1]
        // [...]
    }
}

// daemon/server/router/container/container_routes.go
func (c *containerRouter) postContainersPause(ctx context.Context, w http.ResponseWriter, r *http.Request, vars map[string]string) error {
    // [...]
    if err := c.backend.ContainerPause(vars["name"]); err != nil { // <--------
        return err
    }

    w.WriteHeader(http.StatusNoContent) // response to docker-cli
    return nil
}

// daemon/pause.go
func (daemon *Daemon) ContainerPause(name string) error {
    ctr, err := daemon.GetContainer(name)
    // [...]
    return daemon.containerPause(ctr) // <--------
}

func (daemon *Daemon) containerPause(container *container.Container) error {
    tsk, err := container.GetRunningTask()
    // [...]
    tsk.Pause(context.Background()) // <--------
    // [...]
}

func (t *task) Pause(ctx context.Context) error {
    return t.Task.Pause(ctx) // [2]
}
```

You may not find the definition of `.Pause()` because it invokes the `Task` interface [3] provided by `containerd`.

``` c
// daemon/internal/libcontainerd/remote/client.go
import (
    // [...]
    containerd "github.com/containerd/containerd/v2/client"
    // [...]
)

type task struct {
    containerd.Task // [3]
    ctr *container
}
```

By grepping through the source code of [`containerd`](https://github.com/containerd/containerd), we can see that the `Task`'s pause handler is defined in `client/task.go`. `Pause()` wraps the container ID into a `PauseTaskRequest` [4], which is a **Protobuf-formatted** structure.

``` go
// client/task.go
func (t *task) Pause(ctx context.Context) error {
    // [...]
    _, err := t.client.TaskService().Pause(ctx, &tasks.PauseTaskRequest{  // [4]
        ContainerID: t.id,
    })
    // [...]
}

// api/services/tasks/v1/tasks.pb.go
type PauseTaskRequest struct {
    state         protoimpl.MessageState
    sizeCache     protoimpl.SizeCache
    unknownFields protoimpl.UnknownFields

    ContainerID string `protobuf:"bytes,1,opt,name=container_id,json=containerId,proto3" json:"container_id,omitempty"`
}
```

Noted that there are many versions of `tasks`, and it can be confusing to tell which one is being used. You can identify the correct one by **checking the package name** [5].

``` go
// client/client.go
import (
    // [...]
    "github.com/containerd/containerd/api/services/tasks/v1" // [5]
    // [...]
)

func (c *Client) TaskService() tasks.TasksClient {
    // [...]
    return tasks.NewTasksClient(c.conn) // v1
}
```

Following the function call, the client connection eventually calls `SendMsg()` [6] with the gRPC data as a parameter, sending the Protobuf payload to `containerd` via `containerd.sock`.

``` go
// api/services/tasks/v1/tasks_grpc.pb.go
func (c *tasksClient) Pause(ctx context.Context, in *PauseTaskRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
    out := new(emptypb.Empty)
    err := c.cc.Invoke(ctx, "/containerd.services.tasks.v1.Tasks/Pause", in, out, opts...)
    // [...]
}

// vendor/google.golang.org/grpc/call.go
func (cc *ClientConn) Invoke(ctx context.Context, method string, args, reply any, opts ...CallOption) error {
    opts = combine(cc.dopts.callOptions, opts)
    return invoke(ctx, method, args, reply, cc, opts...) // <--------
}

func Invoke(ctx context.Context, method string, args, reply any, cc *ClientConn, opts ...CallOption) error {
    return cc.Invoke(ctx, method, args, reply, opts...) // <--------
}

var unaryStreamDesc = &StreamDesc{ServerStreams: false, ClientStreams: false}
func invoke(ctx context.Context, method string, req, reply any, cc *ClientConn, opts ...CallOption) error {
    cs, err := newClientStream(ctx, unaryStreamDesc, cc, method, opts...)
    if err := cs.SendMsg(req); err != nil { // [6]
        return err
    }
    return cs.RecvMsg(reply)
}
```

## 3. containerd

The containerd GitHub repo provides a [clear diagram](https://github.com/containerd/containerd/blob/main/docs/historical/design/architecture.png) of its architecture:

<img src="/assets/image-20260526000000000.png" alt="image-20260526000000000" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

For example, according to the diagram, container pausing is related to the container runtime, which is managed by `Task`. In the previous section, we traced the call flow and confirmed that container pausing is actually handled by `containerd.Task` in `dockerd`.

Next, we'll trace the code flow to understand how `containerd` receives and handles requests from `dockerd`.

### 3.1. Receive Requests from dockerd

When the `containerd` daemon runs, the `builtins` and `command` package are imported [1, 2], and `App()` sets up two services: TTRPC (Tiny RPC) [3] and GRPC [4]. Whether the debug service is set up depends on the configuration [5].

``` go
// cmd/containerd/main.go
import (
    // [...]
    "github.com/containerd/containerd/v2/cmd/containerd/command" // [1]
    _ "github.com/containerd/containerd/v2/cmd/containerd/builtins" // [2]
    // [...]
)

func main() {
    app := command.App() // <--------
    if err := app.Run(os.Args); err != nil {
        // [...]
    }
}

// cmd/containerd/command/main.go
func App() *cli.App {
    // [...]
    if config.Debug.Address != "" { // [5]
        var l net.Listener
        if isLocalAddress(config.Debug.Address) {
            if l, err = sys.GetLocalListener(config.Debug.Address, config.Debug.UID, config.Debug.GID); err != nil {
                // [...]
            }
        } else {
            if l, err = net.Listen("tcp", config.Debug.Address); err != nil {
                // [...]
            }
        }
        serve(ctx, l, server.ServeDebug)
    }
    // [...]

    tl, err := sys.GetLocalListener(config.TTRPC.Address, config.TTRPC.UID, config.TTRPC.GID)
    serve(ctx, tl, server.ServeTTRPC) // [3]
    
    // [...]
    
    l, err := sys.GetLocalListener(config.GRPC.Address, config.GRPC.UID, config.GRPC.GID)
    serve(ctx, l, server.ServeGRPC) // [4]
    
    // [...]
}
```

The `builtins` package is a wrapper for built-in packages, and one of the built-in packages it imports is `tasks` [6]. The `init()` function of the `tasks` package is invoked when the package is imported, and it calls `Register()` [7] to register itself with the registry.

``` go
// cmd/containerd/builtins/builtins.go
import (
    // [...]
    _ "github.com/containerd/containerd/v2/plugins/services/tasks" // [6]
    // [...]
)

// plugins/services/tasks/service.go
func init() {
    registry.Register(&plugin.Registration{ // [7]
        Type: plugins.GRPCPlugin,
        ID:   "tasks",
        Requires: []plugin.Type{
            plugins.ServicePlugin,
        },
        InitFn: func(ic *plugin.InitContext) (any, error) {
            i, err := ic.GetByID(plugins.ServicePlugin, services.TasksService)
            if err != nil {
                return nil, err
            }
            return &service{local: i.(api.TasksClient)}, nil
        },
    })
}
```

Later, when the server prepares to run, the `Register()` method of every registered service is called to set up gRPC endpoints based on predefined descriptors [8], and **their handlers are finally attached** [9].

``` go
// plugins/services/tasks/service.go
func (s *service) Register(server *grpc.Server) error {
    api.RegisterTasksServer(server, s) // <--------
    return nil
}

// api/services/tasks/v1/tasks_grpc.pb.go
func RegisterTasksServer(s grpc.ServiceRegistrar, srv TasksServer) {
    s.RegisterService(&Tasks_ServiceDesc, srv) // <--------
}

var Tasks_ServiceDesc = grpc.ServiceDesc{ // [8]
    ServiceName: "containerd.services.tasks.v1.Tasks",
    HandlerType: (*TasksServer)(nil),
    Methods: []grpc.MethodDesc{
        // [...]
        {
            MethodName: "Pause",
            Handler:    _Tasks_Pause_Handler, // [9]
        },
        // [...]
    }
}
```

So if we send a request to the `"/containerd.services.tasks.v1.Tasks/Pause"` gRPC endpoint, `_Tasks_Pause_Handler()` will be invoked.

``` go
func _Tasks_Pause_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
    in := new(PauseTaskRequest)
    info := &grpc.UnaryServerInfo{
        Server:     srv,
        FullMethod: "/containerd.services.tasks.v1.Tasks/Pause",
    }
    handler := func(ctx context.Context, req interface{}) (interface{}, error) {
        return srv.(TasksServer).Pause(ctx, req.(*PauseTaskRequest))
    }
    return interceptor(ctx, in, info, handler)
}
```

### 3.2. Dispatch Request to shim Daemon

To trace the actual handler behind `srv.(TasksServer).Pause()`, we need to go back and find where `TasksServer` comes from. `srv` is the second parameter passed to `RegisterTasksServer()`, and `s` is a `service` object defined in `plugins/services/tasks/service.go` [1].

``` go
// api/services/tasks/v1/tasks_grpc.pb.go
func RegisterTasksServer(s grpc.ServiceRegistrar, srv TasksServer) {
    s.RegisterService(&Tasks_ServiceDesc, srv) // <--------
}

// plugins/services/tasks/service.go
func (s *service) Register(server *grpc.Server) error {
    api.RegisterTasksServer(server, s) // [1]
    return nil
}
```

The `service`'s pause handler then calls `s.local.Pause()` [2], where `local` is assigned from the retrieved initial context `i` object during initialization [3]. The `i` is retrieved by an ID equal to `services.TasksService` [4], which corresponds to the local task object defined in `plugins/services/tasks/local.go` [5].

``` go
// plugins/services/tasks/service.go
func (s *service) Pause(ctx context.Context, r *api.PauseTaskRequest) (*ptypes.Empty, error) {
    return s.local.Pause(ctx, r) // [2]
}

func init() {
    registry.Register(&plugin.Registration{
        // [...]
        InitFn: func(ic *plugin.InitContext) (any, error) {
            // [...]
            i, err := ic.GetByID(plugins.ServicePlugin, services.TasksService) // [4]
            // [...]
            return &service{local: i.(api.TasksClient)}, nil // [3]
        },
    })
}

// plugins/services/tasks/local.go
func init() {
    registry.Register(&plugin.Registration{
        // [...]
        ID:       services.TasksService, // [5]
        // [...]
    })
}
```

The `local` package defines `Pause()`. It first gets the container runtime task object via `l.getTask()` [6] and then calls `t.Pause()` [7]. The process for obtaining task object is somewhat complicated, so I've left some comments to help understand the call flow.

``` go
// plugins/services/tasks/local.go
func (l *local) Pause(ctx context.Context, r *api.PauseTaskRequest, _ ...grpc.CallOption) (*ptypes.Empty, error) {
    // [...]
    t, err := l.getTask(ctx, r.ContainerID) // [6], return runtime.Task
    err = t.Pause(ctx) // [6]
    // [...]
}

func (l *local) getTask(ctx context.Context, id string) (runtime.Task, error) {
    container, err := l.getContainer(ctx, id)
    return l.getTaskFromContainer(ctx, container)
}

func (l *local) getContainer(ctx context.Context, id string) (*containers.Container, error) {
    var container containers.Container
    // 'initFunc()' set 'l.containers' to 'metadata.NewContainerStore(db)'
    container, err := l.containers.Get(ctx, id) // call 'Get()' in 'core/metadata/containers.go'
                                                // -> get container from db
    return &container
}

func (l *local) getTaskFromContainer(ctx context.Context, container *containers.Container) (runtime.Task, error) {
    /**
     * initFunc() set 'l.v2Runtime' to 'v2r.(runtime.PlatformRuntime)'
     * -> v2r is from 'ic.GetByID(plugins.RuntimePluginV2, "task")'
     * -> init() 'core/runtime/v2/task_manager.go' register 'plugins.RuntimePluginV2'
     * -> Get() return 'newShimTask(shim)', which is defined in 'core/runtime/v2/shim.go'
     * -> shimTask is the actual structure which is extended from runtime.Task interface
     */
    t, err := l.v2Runtime.Get(ctx, container.ID)
    return t
}
```

The `task` object of the `t.Pause()` call is returned from `newShimTask(shim)` in the `v2` package, so we can see that `t.Pause()` corresponds to the `Pause()` handler in the same package [8]. It then calls `s.task.Pause()`, whose definition lives in its task client, and `s.task` is created by `NewTaskClient()` [10].

``` go
// core/runtime/v2/shim.go
package v2

func newShimTask(shim ShimInstance) (*shimTask, error) {
    _, version := shim.Endpoint()
    taskClient, err := NewTaskClient(shim.Client(), version) // [10]
    // [...]
    return &shimTask{
        ShimInstance: shim,
        task:         taskClient, // [9]
    }, nil
}

func (s *shimTask) Pause(ctx context.Context) error { // [8]
    /**
     * s.task is assigned to NewTaskClient()'s return value, which calls a switch case with client type and version
     * - ttrpc + v2 -> *ttrpcV2Bridge
     * - ttrpc + v3 -> api.NewTTRPCTaskClient
     * - grpc + v3  -> *grpcV3Bridge
     */
    if _, err := s.task.Pause(ctx, &task.PauseRequest{
        ID: s.ID(),
    }) // [...]
}
```

`NewTaskClient()` returns different `TTRPCTaskService` object depending on the **type** and **version**. For a TTRPC client with version 2, a `ttrpctaskClient` object is created [11]. Finally, we wrap the TTRPC message and send it [12] to the service `"containerd.task.v2.Task"` with method `"Pause"` through the shim daemon socket.

``` go
// core/runtime/v2/bridge.go
func NewTaskClient(client any, version int) (TaskServiceClient, error) {
    switch c := client.(type) {
    case *ttrpc.Client:
        switch version {
        case 2:
            return &ttrpcV2Bridge{client: v2.NewTTRPCTaskClient(c)}, nil // <--------
        case 3:
            return api.NewTTRPCTaskClient(c), nil
        // [...]
        }

    case grpc.ClientConnInterface:
        // [...]
        if version != 3 {
            // [...]
        }
        return &grpcV3Bridge{api.NewTaskClient(c)}, nil
    // [...]
    }
}

// api/runtime/task/v2/shim_ttrpc.pb.go
func NewTTRPCTaskClient(client *ttrpc.Client) TTRPCTaskService {
    return &ttrpctaskClient{ // [11]
        client: client,
    }
}

func (c *ttrpctaskClient) Pause(ctx context.Context, req *PauseRequest) (*emptypb.Empty, error) {
    var resp emptypb.Empty
    if err := c.client.Call(ctx, "containerd.task.v2.Task", "Pause", req, &resp); err != nil { // [12]
        return nil, err
    }
    return &resp, nil
}
```

## 4. containerd-shim-runc-v2 (shim Daemon)

Every container **needs a `shim` daemon** to hold its stdio, wait for its init process, and report exit status back to `containerd`. This also decouples the container's lifecycle from `containerd` itself: if `containerd` crashes or gets restarted, the `shim` keeps running, the container stays alive, and `containerd` can later re-attach to the `shim` daemon to recover state. As a result, a shim daemon exposes the Unix socket, allowing `containerd` to indirectly control the container.

When a `shim` daemon initializes, the main function `run()` iterates through all predefined service objects [1] and register each as a TTRPC service [2].

``` go
// pkg/shim/shim.go
func run(ctx context.Context, manager Manager, config Config) error {
    // [...]
    for _, p := range registry.Graph(func(*plugin.Registration) bool { return false }) {
        ttrpcServices = append(ttrpcServices, src) // [1]
    }
    // [...]
    for _, srv := range ttrpcServices {
        if err := srv.RegisterTTRPC(server); err != nil { // [2]
            // [...]
        }
    }
    // [...]
}
```

The `task` package's register function calls `RegisterService()` with endpoint descriptors, one of which is `"Pause"` [3].

``` go
// cmd/containerd-shim-runc-v2/task/service.go
func (s *service) RegisterTTRPC(server *ttrpc.Server) error {
    taskAPI.RegisterTTRPCTaskService(server, s) // <--------
    return nil
}

func RegisterTTRPCTaskService(srv *ttrpc.Server, svc TTRPCTaskService) {
    srv.RegisterService("containerd.task.v2.Task", &ttrpc.ServiceDesc{
        Methods: map[string]ttrpc.Method{
            ...
            "Pause": func(ctx context.Context, unmarshal func(interface{}) error) (interface{}, error) { // [3]
                var req PauseRequest
                if err := unmarshal(&req); err != nil { return nil, err }
                return svc.Pause(ctx, &req)
            },
            ...
        },
    })
}
```

The `svc.Pause()` ends up at the `Pause()` function in `containerd/go-runc/runc.go`, which actually runs the command `runc pause <id>` [4] to pause the container. Interesting!

``` go
// cmd/containerd-shim-runc-v2/task/service.go
func (s *service) Pause(ctx context.Context, r *taskAPI.PauseRequest) (*ptypes.Empty, error) {
    container, err := s.getContainer(r.ID)
    if err := container.Pause(ctx); err != nil { // <--------
        // [...]
    }
    s.send(&eventstypes.TaskPaused{
        ContainerID: container.ID,
    })
    // [...]
}

// cmd/containerd-shim-runc-v2/runc/container.go
func (c *Container) Pause(ctx context.Context) error {
    return c.process.(*process.Init).Pause(ctx) // <--------
}

// cmd/containerd-shim-runc-v2/process/init.go
func (p *Init) Pause(ctx context.Context) error {
    // [...]
    return p.initState.Pause(ctx) // <--------
}

// cmd/containerd-shim-runc-v2/process/init_state.go
func (s *runningState) Pause(ctx context.Context) error {
    // [...]
    if err := s.p.runtime.Pause(ctx, s.p.id); err != nil { // <--------
        // [...]
    }
    // [...]
}

// vendor/github.com/containerd/go-runc/runc.go
func (r *Runc) Pause(context context.Context, id string) error {
    return r.runOrError(r.command(context, "pause", id)) // [4]
}
```

## 5. runc

From the previous section, we learned that the shim daemon handles the pause container request by **forking a new process and executing `runc`**. But what exactly is `runc`?

[runc](https://github.com/opencontainers/runc) is a **low-level container runtime** implementation, or you can say an OCI (Open Container Initiative) runtime. Its job is to directly control a container, such as creating a new container, listing all processes inside a container, and so on.

We'll continue using "pause a container" as our example. The variable `pauseCommand` in `pause.go` defines how the pause command works, and other commands follow a similar pattern: a file named `<command_name>.go` with a corresponding variable `<command_name>Command`.

The `Action` field shows the implementation: check arguments, get the container, and pause it [1].

``` go
// pause.go
var pauseCommand = &cli.Command{
    Name:  "pause",
    Usage: "pause suspends all processes inside the container",
    ArgsUsage: `<container-id>

Where "<container-id>" is the name for the instance of the container to be
paused. `,
    Description: `The pause command suspends all processes in the instance of the container.

Use runc list to identify instances of containers and their current status.`,
    // Disable comma as separator for slice flags.
    DisableSliceFlagSeparator: true,
    Action: func(_ context.Context, cmd *cli.Command) error {
        if err := checkArgs(cmd, 1, exactArgs); err != nil {
            return err
        }
        container, err := getContainer(cmd)
        // [...]
        err = container.Pause() // [1]
        // [...]
        return nil
    },
}
```

`Pause()` checks whether the container has been created or is still running, and then calls `c.cgroupManager.Freeze()` [2]. There are two cgroup versions: v1 and v2, so `c.cgroupManager` could be either version. Here, we'll assume v2 is being used.

``` go
// libcontainer/container_linux.go
func (c *Container) Pause() error {
    // [...]
    status, err := c.currentStatus()
    // [...]
    switch status {
    case Running, Created:
        if err := c.cgroupManager.Freeze(cgroups.Frozen); err != nil { // [2]
            return err
        }
        // [...]
    }
    // [...]
}
```

Cgroup version 2, referred to as `cgroupv2` in the code, uses `fs2` as its filesystem manager, and the `Freeze()` handler in turn calls `setFreezer()` [3].

``` go
// vendor/github.com/opencontainers/cgroups/systemd/v2.go
func (m *UnifiedManager) Freeze(state cgroups.FreezerState) error {
    // m.fsMgr is assigned to 'fs2.NewManager(config, m.path)' in NewUnifiedManager()
    return m.fsMgr.Freeze(state) // <--------
}

// vendor/github.com/opencontainers/cgroups/fs2/fs2.go
func (m *Manager) Freeze(state cgroups.FreezerState) error {
    // [...]
    if err := setFreezer(m.dirPath, state); err != nil { // [3]
        return err
    }
    // [...]
}
```

The freezer modifies the pseudo-file `cgroup.freeze` [4, 5] to **update the status of the associated container**, causing it to be frozen.

``` go
// vendor/github.com/opencontainers/cgroups/fs2/freezer.go
func setFreezer(dirPath string, state cgroups.FreezerState) error {
    // [...]
    fd, err := cgroups.OpenFile(dirPath, "cgroup.freeze", unix.O_RDWR) // [4]
    // [...]
    if _, err := fd.WriteString(stateStr); err != nil { // [5]
        // [...]
    }
    // [...]
}
```

## 6. Summary

The first post only focuses on the communication methods and the relationship between each component. In the next two posts, I will cover the attack surfaces and some past vulnerabilities, as well as the NVIDIA toolkit implementation.
