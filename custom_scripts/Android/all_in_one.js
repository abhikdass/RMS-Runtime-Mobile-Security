const commonPaths = [
    "/data/local/bin/su",
    "/data/local/su",
    "/data/local/xbin/su",
    "/dev/com.koushikdutta.superuser.daemon/",
    "/sbin/su",
    "/system/app/Superuser.apk",
    "/system/bin/failsafe/su",
    "/system/bin/su",
    "/su/bin/su",
    "/system/etc/init.d/99SuperSUDaemon",
    "/system/sd/xbin/su",
    "/system/xbin/busybox",
    "/system/xbin/daemonsu",
    "/system/xbin/su",
    "/system/sbin/su",
    "/vendor/bin/su",
    "/cache/su",
    "/data/su",
    "/dev/su",
    "/system/bin/.ext/su",
    "/system/usr/we-need-root/su",
    "/system/app/Kinguser.apk",
    "/data/adb/magisk",
    "/sbin/.magisk",
    "/cache/.disable_magisk",
    "/dev/.magisk.unblock",
    "/cache/magisk.log",
    "/data/adb/magisk.img",
    "/data/adb/magisk.db",
    "/data/adb/magisk_simple",
    "/init.magisk.rc",
    "/system/xbin/ku.sud",
    "/data/adb/ksu",
    "/data/adb/ksud",
];

const ROOTmanagementApp = [
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro",
    "com.topjohnwu.magisk",
    "me.weishu.kernelsu",
];

/**
 * Bypass Emulator Detection
 * @param {any} function(
 * @returns {any}
 */
Java.perform(function() {

    Java.use("android.os.Build").PRODUCT.value = "gracerltexx";
    Java.use("android.os.Build").MANUFACTURER.value = "samsung";
    Java.use("android.os.Build").BRAND.value = "samsung";
    Java.use("android.os.Build").DEVICE.value = "gracerlte";
    Java.use("android.os.Build").MODEL.value = "SM-N935F";
    Java.use("android.os.Build").HARDWARE.value = "samsungexynos8890";
    Java.use("android.os.Build").FINGERPRINT.value =
        "samsung/gracerltexx/gracerlte:8.0.0/R16NW/N935FXXS4BRK2:user/release-keys";


    try {
        Java.use("java.io.File").exists.implementation = function() {
            var name = Java.use("java.io.File").getName.call(this);
            var catched = ["qemud", "qemu_pipe", "drivers", "cpuinfo"].indexOf(name) > -1;
            if (catched) {
                send("the pipe " + name + " existence is hooked");
                return false;
            } else {
                return this.exists.call(this);
            }
        };
    } catch (err) {
        send("[-] java.io.File.exists never called [-]");
    }

    // rename the package names
    try {
        Java.use("android.app.ApplicationPackageManager").getPackageInfo.overload(
            "java.lang.String",
            "int"
        ).implementation = function(name, flag) {
            var catched = ["com.example.android.apis", "com.android.development"].indexOf(name) >
                -1;
            if (catched) {
                send("the package " + name + " is renamed with fake name");
                name = "fake.package.name";
            }
            return this.getPackageInfo.call(this, name, flag);
        };
    } catch (err) {
        send(
            "[-] ApplicationPackageManager.getPackageInfo never called [-]"
        );
    }

    // hook the `android_getCpuFamily` method
    // https://android.googlesource.com/platform/ndk/+/master/sources/android/cpufeatures/cpu-features.c#1067
    // Note: If you pass "null" as the first parameter for "Module.findExportByName" it will search in all modules
    try {
        Interceptor.attach(Module.findExportByName(null, "android_getCpuFamily"), {
            onLeave: function(retval) {
                // const int ANDROID_CPU_FAMILY_X86 = 2;
                // const int ANDROID_CPU_FAMILY_X86_64 = 5;
                if ([2, 5].indexOf(retval) > -1) {
                    // const int ANDROID_CPU_FAMILY_ARM64 = 4;
                    retval.replace(4);
                }
            },
        });
    } catch (err) {
        send("[-] android_getCpuFamily never called [-]");
        // TODO: trace RegisterNatives in case the libraries are stripped.
    }
});

/**
 * Bypass Root Detection
 * @param {any} function(
 * @returns {any}
 */
setTimeout(function() {
    function stackTraceHere(isLog) {
        var Exception = Java.use("java.lang.Exception");
        var Log = Java.use("android.util.Log");
        var stackinfo = Log.getStackTraceString(Exception.$new());
        if (isLog) {
            send(stackinfo);
        } else {
            return stackinfo;
        }
    }

    function stackTraceNativeHere(isLog) {
        var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress)
            .join("\n\t");
        send(backtrace);
    }

    function bypassJavaFileCheck() {
        var UnixFileSystem = Java.use("java.io.UnixFileSystem");
        UnixFileSystem.checkAccess.implementation = function(file, access) {
            var stack = stackTraceHere(false);

            const filename = file.getAbsolutePath();

            if (filename.indexOf("magisk") >= 0) {
                send("Anti Root Detect - check file: " + filename);
                return false;
            }

            if (commonPaths.indexOf(filename) >= 0) {
                send("Anti Root Detect - check file: " + filename);
                return false;
            }

            return this.checkAccess(file, access);
        };
    }

    function bypassNativeFileCheck() {
        var fopen = Module.findExportByName("libc.so", "fopen");
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                this.inputPath = args[0].readUtf8String();
            },
            onLeave: function(retval) {
                if (retval.toInt32() != 0) {
                    if (commonPaths.indexOf(this.inputPath) >= 0) {
                        send("Anti Root Detect - fopen : " + this.inputPath);
                        retval.replace(ptr(0x0));
                    }
                }
            },
        });

        var access = Module.findExportByName("libc.so", "access");
        Interceptor.attach(access, {
            onEnter: function(args) {
                this.inputPath = args[0].readUtf8String();
            },
            onLeave: function(retval) {
                if (retval.toInt32() == 0) {
                    if (commonPaths.indexOf(this.inputPath) >= 0) {
                        send("Anti Root Detect - access : " + this.inputPath);
                        retval.replace(ptr(-1));
                    }
                }
            },
        });
    }

    function setProp() {
        var Build = Java.use("android.os.Build");
        var TAGS = Build.class.getDeclaredField("TAGS");
        TAGS.setAccessible(true);
        TAGS.set(null, "release-keys");

        var FINGERPRINT = Build.class.getDeclaredField("FINGERPRINT");
        FINGERPRINT.setAccessible(true);
        FINGERPRINT.set(
            null,
            "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys"
        );

        // Build.deriveFingerprint.inplementation = function(){
        //     var ret = this.deriveFingerprint() //该函数无法通过反射调用
        //     send(ret)
        //     return ret
        // }

        var system_property_get = Module.findExportByName(
            "libc.so",
            "__system_property_get"
        );
        Interceptor.attach(system_property_get, {
            onEnter(args) {
                this.key = args[0].readCString();
                this.ret = args[1];
            },
            onLeave(ret) {
                if (this.key == "ro.build.fingerprint") {
                    var tmp =
                        "google/crosshatch/crosshatch:10/QQ3A.200805.001/6578210:user/release-keys";
                    var p = Memory.allocUtf8String(tmp);
                    Memory.copy(this.ret, p, tmp.length + 1);
                }
            },
        });
    }

    //android.app.PackageManager
    function bypassRootAppCheck() {
        var ApplicationPackageManager = Java.use(
            "android.app.ApplicationPackageManager"
        );
        ApplicationPackageManager.getPackageInfo.overload(
            "java.lang.String",
            "int"
        ).implementation = function(str, i) {
            // send(str)
            if (ROOTmanagementApp.indexOf(str) >= 0) {
                send("Anti Root Detect - check package : " + str);
                str = "ashen.one.ye.not.found";
            }
            return this.getPackageInfo(str, i);
        };

        //shell pm check
    }

    function bypassShellCheck() {
        var String = Java.use("java.lang.String");

        var ProcessImpl = Java.use("java.lang.ProcessImpl");
        ProcessImpl.start.implementation = function(
            cmdarray,
            env,
            dir,
            redirects,
            redirectErrorStream
        ) {
            if (cmdarray[0] == "mount") {
                send("Anti Root Detect - Shell : " + cmdarray.toString());
                arguments[0] = Java.array("java.lang.String", [String.$new("")]);
                return ProcessImpl.start.apply(this, arguments);
            }

            if (cmdarray[0] == "getprop") {
                send("Anti Root Detect - Shell : " + cmdarray.toString());
                const prop = ["ro.secure", "ro.debuggable"];
                if (prop.indexOf(cmdarray[1]) >= 0) {
                    arguments[0] = Java.array("java.lang.String", [String.$new("")]);
                    return ProcessImpl.start.apply(this, arguments);
                }
            }

            if (cmdarray[0].indexOf("which") >= 0) {
                const prop = ["su"];
                if (prop.indexOf(cmdarray[1]) >= 0) {
                    send("Anti Root Detect - Shell : " + cmdarray.toString());
                    arguments[0] = Java.array("java.lang.String", [String.$new("")]);
                    return ProcessImpl.start.apply(this, arguments);
                }
            }

            return ProcessImpl.start.apply(this, arguments);
        };
    }

    send("Attach");
    bypassNativeFileCheck();
    bypassJavaFileCheck();
    setProp();
    bypassRootAppCheck();
    bypassShellCheck();


    Java.perform(function() {
        var RootPackages = [
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.koushikdutta.rommanager",
            "com.koushikdutta.rommanager.license",
            "com.dimonvideo.luckypatcher",
            "com.chelpus.lackypatch",
            "com.ramdroid.appquarantine",
            "com.ramdroid.appquarantinepro",
            "com.devadvance.rootcloak",
            "com.devadvance.rootcloakplus",
            "de.robv.android.xposed.installer",
            "com.saurik.substrate",
            "com.zachspong.temprootremovejb",
            "com.amphoras.hidemyroot",
            "com.amphoras.hidemyrootadfree",
            "com.formyhm.hiderootPremium",
            "com.formyhm.hideroot",
            "me.phh.superuser",
            "eu.chainfire.supersu.pro",
            "com.kingouser.com",
            "com.topjohnwu.magisk",
        ];

        var RootBinaries = [
            "su",
            "busybox",
            "supersu",
            "Superuser.apk",
            "KingoUser.apk",
            "SuperSu.apk",
            "magisk",
        ];

        var RootProperties = {
            "ro.build.selinux": "1",
            "ro.debuggable": "0",
            "service.adb.root": "0",
            "ro.secure": "1",
        };

        var RootPropertiesKeys = [];

        for (var k in RootProperties) RootPropertiesKeys.push(k);

        var PackageManager = Java.use("android.app.ApplicationPackageManager");

        var Runtime = Java.use("java.lang.Runtime");

        var NativeFile = Java.use("java.io.File");

        var String = Java.use("java.lang.String");

        var SystemProperties = Java.use("android.os.SystemProperties");

        var BufferedReader = Java.use("java.io.BufferedReader");

        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");

        var StringBuffer = Java.use("java.lang.StringBuffer");

        var loaded_classes = Java.enumerateLoadedClassesSync();

        send("Loaded " + loaded_classes.length + " classes!");

        var useKeyInfo = false;

        var useProcessManager = false;

        send("loaded: " + loaded_classes.indexOf("java.lang.ProcessManager"));

        if (loaded_classes.indexOf("java.lang.ProcessManager") != -1) {
            try {
                //useProcessManager = true;
                //var ProcessManager = Java.use('java.lang.ProcessManager');
            } catch (err) {
                send("ProcessManager Hook failed: " + err);
            }
        } else {
            send("ProcessManager hook not loaded");
        }

        var KeyInfo = null;

        if (loaded_classes.indexOf("android.security.keystore.KeyInfo") != -1) {
            try {
                //useKeyInfo = true;
                //var KeyInfo = Java.use('android.security.keystore.KeyInfo');
            } catch (err) {
                send("KeyInfo Hook failed: " + err);
            }
        } else {
            send("KeyInfo hook not loaded");
        }

        PackageManager.getPackageInfo.overload(
            "java.lang.String",
            "int"
        ).implementation = function(pname, flags) {
            var shouldFakePackage = RootPackages.indexOf(pname) > -1;
            if (shouldFakePackage) {
                send("Bypass root check for package: " + pname);
                pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
            }
            return this.getPackageInfo
                .overload("java.lang.String", "int")
                .call(this, pname, flags);
        };

        NativeFile.exists.implementation = function() {
            var name = NativeFile.getName.call(this);
            var shouldFakeReturn = RootBinaries.indexOf(name) > -1;
            if (shouldFakeReturn) {
                send("Bypass return value for binary: " + name);
                return false;
            } else {
                return this.exists.call(this);
            }
        };

        var exec = Runtime.exec.overload("[Ljava.lang.String;");
        var exec1 = Runtime.exec.overload("java.lang.String");
        var exec2 = Runtime.exec.overload("java.lang.String", "[Ljava.lang.String;");
        var exec3 = Runtime.exec.overload(
            "[Ljava.lang.String;",
            "[Ljava.lang.String;"
        );
        var exec4 = Runtime.exec.overload(
            "[Ljava.lang.String;",
            "[Ljava.lang.String;",
            "java.io.File"
        );
        var exec5 = Runtime.exec.overload(
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.io.File"
        );

        exec5.implementation = function(cmd, env, dir) {
            if (
                cmd.indexOf("getprop") != -1 ||
                cmd == "mount" ||
                cmd.indexOf("build.prop") != -1 ||
                cmd == "id" ||
                cmd == "sh"
            ) {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd =
                    "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec5.call(this, cmd, env, dir);
        };

        exec4.implementation = function(cmdarr, env, file) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (
                    tmp_cmd.indexOf("getprop") != -1 ||
                    tmp_cmd == "mount" ||
                    tmp_cmd.indexOf("build.prop") != -1 ||
                    tmp_cmd == "id" ||
                    tmp_cmd == "sh"
                ) {
                    var fakeCmd = "grep";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd =
                        "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec4.call(this, cmdarr, env, file);
        };

        exec3.implementation = function(cmdarr, envp) {
            for (var i = 0; i < cmdarr.length; i = i + 1) {
                var tmp_cmd = cmdarr[i];
                if (
                    tmp_cmd.indexOf("getprop") != -1 ||
                    tmp_cmd == "mount" ||
                    tmp_cmd.indexOf("build.prop") != -1 ||
                    tmp_cmd == "id" ||
                    tmp_cmd == "sh"
                ) {
                    var fakeCmd = "grep";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd =
                        "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmdarr + " command");
                    return exec1.call(this, fakeCmd);
                }
            }
            return exec3.call(this, cmdarr, envp);
        };

        exec2.implementation = function(cmd, env) {
            if (
                cmd.indexOf("getprop") != -1 ||
                cmd == "mount" ||
                cmd.indexOf("build.prop") != -1 ||
                cmd == "id" ||
                cmd == "sh"
            ) {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd =
                    "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec2.call(this, cmd, env);
        };

        exec.implementation = function(cmd) {
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (
                    tmp_cmd.indexOf("getprop") != -1 ||
                    tmp_cmd == "mount" ||
                    tmp_cmd.indexOf("build.prop") != -1 ||
                    tmp_cmd == "id" ||
                    tmp_cmd == "sh"
                ) {
                    var fakeCmd = "grep";
                    send("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }

                if (tmp_cmd == "su") {
                    var fakeCmd =
                        "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                    send("Bypass " + cmd + " command");
                    return exec1.call(this, fakeCmd);
                }
            }

            return exec.call(this, cmd);
        };

        exec1.implementation = function(cmd) {
            if (
                cmd.indexOf("getprop") != -1 ||
                cmd == "mount" ||
                cmd.indexOf("build.prop") != -1 ||
                cmd == "id" ||
                cmd == "sh"
            ) {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            if (cmd == "su") {
                var fakeCmd =
                    "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
            return exec1.call(this, cmd);
        };

        String.contains.implementation = function(name) {
            if (name == "test-keys") {
                send("Bypass test-keys check");
                return false;
            }
            return this.contains.call(this, name);
        };

        var get = SystemProperties.get.overload("java.lang.String");

        get.implementation = function(name) {
            if (RootPropertiesKeys.indexOf(name) != -1) {
                send("Bypass " + name);
                return RootProperties[name];
            }
            return this.get.call(this, name);
        };

        Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
            onEnter: function(args) {
                var path = Memory.readCString(args[0]);
                path = path.split("/");
                var executable = path[path.length - 1];
                var shouldFakeReturn = RootBinaries.indexOf(executable) > -1;
                if (shouldFakeReturn) {
                    Memory.writeUtf8String(args[0], "/notexists");
                    send("Bypass native fopen");
                }
            },
            onLeave: function(retval) {},
        });

        Interceptor.attach(Module.findExportByName("libc.so", "system"), {
            onEnter: function(args) {
                var cmd = Memory.readCString(args[0]);
                send("SYSTEM CMD: " + cmd);
                if (
                    cmd.indexOf("getprop") != -1 ||
                    cmd == "mount" ||
                    cmd.indexOf("build.prop") != -1 ||
                    cmd == "id"
                ) {
                    send("Bypass native system: " + cmd);
                    Memory.writeUtf8String(args[0], "grep");
                }
                if (cmd == "su") {
                    send("Bypass native system: " + cmd);
                    Memory.writeUtf8String(
                        args[0],
                        "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"
                    );
                }
            },
            onLeave: function(retval) {},
        });

        /*

        TO IMPLEMENT:

        Exec Family

        int execl(const char *path, const char *arg0, ..., const char *argn, (char *)0);
        int execle(const char *path, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execlp(const char *file, const char *arg0, ..., const char *argn, (char *)0);
        int execlpe(const char *file, const char *arg0, ..., const char *argn, (char *)0, char *const envp[]);
        int execv(const char *path, char *const argv[]);
        int execve(const char *path, char *const argv[], char *const envp[]);
        int execvp(const char *file, char *const argv[]);
        int execvpe(const char *file, char *const argv[], char *const envp[]);

        */

        BufferedReader.readLine.overload("boolean").implementation = function() {
            var text = this.readLine.overload("boolean").call(this);
            if (text === null) {
                // just pass , i know it's ugly as hell but test != null won't work :(
            } else {
                var shouldFakeRead = text.indexOf("ro.build.tags=test-keys") > -1;
                if (shouldFakeRead) {
                    send("Bypass build.prop file read");
                    text = text.replace(
                        "ro.build.tags=test-keys",
                        "ro.build.tags=release-keys"
                    );
                }
            }
            return text;
        };

        var executeCommand = ProcessBuilder.command.overload("java.util.List");

        ProcessBuilder.start.implementation = function() {
            var cmd = this.command.call(this);
            var shouldModifyCommand = false;
            for (var i = 0; i < cmd.size(); i = i + 1) {
                var tmp_cmd = cmd.get(i).toString();
                if (
                    tmp_cmd.indexOf("getprop") != -1 ||
                    tmp_cmd.indexOf("mount") != -1 ||
                    tmp_cmd.indexOf("build.prop") != -1 ||
                    tmp_cmd.indexOf("id") != -1
                ) {
                    shouldModifyCommand = true;
                }
            }
            if (shouldModifyCommand) {
                send("Bypass ProcessBuilder " + cmd);
                this.command.call(this, ["grep"]);
                return this.start.call(this);
            }
            if (cmd.indexOf("su") != -1) {
                send("Bypass ProcessBuilder " + cmd);
                this.command.call(this, [
                    "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled",
                ]);
                return this.start.call(this);
            }

            return this.start.call(this);
        };

        if (useProcessManager) {
            var ProcManExec = ProcessManager.exec.overload(
                "[Ljava.lang.String;",
                "[Ljava.lang.String;",
                "java.io.File",
                "boolean"
            );
            var ProcManExecVariant = ProcessManager.exec.overload(
                "[Ljava.lang.String;",
                "[Ljava.lang.String;",
                "java.lang.String",
                "java.io.FileDescriptor",
                "java.io.FileDescriptor",
                "java.io.FileDescriptor",
                "boolean"
            );

            ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (
                        tmp_cmd.indexOf("getprop") != -1 ||
                        tmp_cmd == "mount" ||
                        tmp_cmd.indexOf("build.prop") != -1 ||
                        tmp_cmd == "id"
                    ) {
                        var fake_cmd = ["grep"];
                        send("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = [
                            "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled",
                        ];
                        send("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
            };

            ProcManExecVariant.implementation = function(
                cmd,
                env,
                directory,
                stdin,
                stdout,
                stderr,
                redirect
            ) {
                var fake_cmd = cmd;
                for (var i = 0; i < cmd.length; i = i + 1) {
                    var tmp_cmd = cmd[i];
                    if (
                        tmp_cmd.indexOf("getprop") != -1 ||
                        tmp_cmd == "mount" ||
                        tmp_cmd.indexOf("build.prop") != -1 ||
                        tmp_cmd == "id"
                    ) {
                        var fake_cmd = ["grep"];
                        send("Bypass " + cmdarr + " command");
                    }

                    if (tmp_cmd == "su") {
                        var fake_cmd = [
                            "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled",
                        ];
                        send("Bypass " + cmdarr + " command");
                    }
                }
                return ProcManExecVariant.call(
                    this,
                    fake_cmd,
                    env,
                    directory,
                    stdin,
                    stdout,
                    stderr,
                    redirect
                );
            };
        }

        if (useKeyInfo) {
            KeyInfo.isInsideSecureHardware.implementation = function() {
                send("Bypass isInsideSecureHardware");
                return true;
            };
        }
    });

}, 0);

/**
 * Bypass Multiple SSL Pinning
 * @param {any} function(
 * @returns {any}
 */
setTimeout(function() {
    Java.perform(function() {
        send("---");
        send("Unpinning Android app...");

        /// -- Generic hook to protect against SSLPeerUnverifiedException -- ///

        // In some cases, with unusual cert pinning approaches, or heavy obfuscation, we can't
        // match the real method & package names. This is a problem! Fortunately, we can still
        // always match built-in types, so here we spot all failures that use the built-in cert
        // error type (notably this includes OkHttp), and after the first failure, we dynamically
        // generate & inject a patch to completely disable the method that threw the error.
        try {
            const UnverifiedCertError = Java.use(
                "javax.net.ssl.SSLPeerUnverifiedException"
            );
            UnverifiedCertError.$init.implementation = function(str) {
                send(
                    "  --> Unexpected SSL verification failure, adding dynamic patch..."
                );

                try {
                    const stackTrace = Java.use("java.lang.Thread")
                        .currentThread()
                        .getStackTrace();
                    const exceptionStackIndex = stackTrace.findIndex(
                        (stack) =>
                        stack.getClassName() ===
                        "javax.net.ssl.SSLPeerUnverifiedException"
                    );
                    const callingFunctionStack = stackTrace[exceptionStackIndex + 1];

                    const className = callingFunctionStack.getClassName();
                    const methodName = callingFunctionStack.getMethodName();

                    send(`      Thrown by ${className}->${methodName}`);

                    const callingClass = Java.use(className);
                    const callingMethod = callingClass[methodName];

                    if (callingMethod.implementation) return; // Already patched by Frida - skip it

                    send("      Attempting to patch automatically...");
                    const returnTypeName = callingMethod.returnType.type;

                    callingMethod.implementation = function() {
                        send(
                            `  --> Bypassing ${className}->${methodName} (automatic exception patch)`
                        );

                        // This is not a perfect fix! Most unknown cases like this are really just
                        // checkCert(cert) methods though, so doing nothing is perfect, and if we
                        // do need an actual return value then this is probably the best we can do,
                        // and at least we're logging the method name so you can patch it manually:

                        if (returnTypeName === "void") {
                            return;
                        } else {
                            return null;
                        }
                    };

                    send(
                        `      [+] ${className}->${methodName} (automatic exception patch)`
                    );
                } catch (e) {
                    send("      [ ] Failed to automatically patch failure");
                }

                return this.$init(str);
            };
            send("[+] SSLPeerUnverifiedException auto-patcher");
        } catch (err) {
            send("[ ] SSLPeerUnverifiedException auto-patcher");
        }

        /// -- Specific targeted hooks: -- ///

        // HttpsURLConnection
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(
                hostnameVerifier
            ) {
                send(
                    "  --> Bypassing HttpsURLConnection (setDefaultHostnameVerifier)"
                );
                return; // Do nothing, i.e. don't change the hostname verifier
            };
            send("[+] HttpsURLConnection (setDefaultHostnameVerifier)");
        } catch (err) {
            send("[ ] HttpsURLConnection (setDefaultHostnameVerifier)");
        }
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setSSLSocketFactory.implementation = function(
                SSLSocketFactory
            ) {
                send("  --> Bypassing HttpsURLConnection (setSSLSocketFactory)");
                return; // Do nothing, i.e. don't change the SSL socket factory
            };
            send("[+] HttpsURLConnection (setSSLSocketFactory)");
        } catch (err) {
            send("[ ] HttpsURLConnection (setSSLSocketFactory)");
        }
        try {
            const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setHostnameVerifier.implementation = function(
                hostnameVerifier
            ) {
                send("  --> Bypassing HttpsURLConnection (setHostnameVerifier)");
                return; // Do nothing, i.e. don't change the hostname verifier
            };
            send("[+] HttpsURLConnection (setHostnameVerifier)");
        } catch (err) {
            send("[ ] HttpsURLConnection (setHostnameVerifier)");
        }

        // SSLContext
        try {
            const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            const SSLContext = Java.use("javax.net.ssl.SSLContext");

            const TrustManager = Java.registerClass({
                // Implement a custom TrustManager
                name: "dev.asd.test.TrustManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() {
                        return [];
                    },
                },
            });

            // Prepare the TrustManager array to pass to SSLContext.init()
            const TrustManagers = [TrustManager.$new()];

            // Get a handle on the init() on the SSLContext class
            const SSLContext_init = SSLContext.init.overload(
                "[Ljavax.net.ssl.KeyManager;",
                "[Ljavax.net.ssl.TrustManager;",
                "java.security.SecureRandom"
            );

            // Override the init method, specifying the custom TrustManager
            SSLContext_init.implementation = function(
                keyManager,
                trustManager,
                secureRandom
            ) {
                send("  --> Bypassing Trustmanager (Android < 7) request");
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
            send("[+] SSLContext");
        } catch (err) {
            send("[ ] SSLContext");
        }

        // TrustManagerImpl (Android > 7)
        try {
            const array_list = Java.use("java.util.ArrayList");
            const TrustManagerImpl = Java.use(
                "com.android.org.conscrypt.TrustManagerImpl"
            );

            // This step is notably what defeats the most common case: network security config
            TrustManagerImpl.checkTrustedRecursive.implementation = function(
                a1,
                a2,
                a3,
                a4,
                a5,
                a6
            ) {
                send("  --> Bypassing TrustManagerImpl checkTrusted ");
                return array_list.$new();
            };

            TrustManagerImpl.verifyChain.implementation = function(
                untrustedChain,
                trustAnchorChain,
                host,
                clientAuth,
                ocspData,
                tlsSctData
            ) {
                send("  --> Bypassing TrustManagerImpl verifyChain: " + host);
                return untrustedChain;
            };
            send("[+] TrustManagerImpl");
        } catch (err) {
            send("[ ] TrustManagerImpl");
        }

        // OkHTTPv3 (quadruple bypass)
        try {
            // Bypass OkHTTPv3 {1}
            const okhttp3_Activity_1 = Java.use("okhttp3.CertificatePinner");
            okhttp3_Activity_1.check.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function(a, b) {
                send("  --> Bypassing OkHTTPv3 (list): " + a);
                return;
            };
            send("[+] OkHTTPv3 (list)");
        } catch (err) {
            send("[ ] OkHTTPv3 (list)");
        }
        try {
            // Bypass OkHTTPv3 {2}
            // This method of CertificatePinner.check could be found in some old Android app
            const okhttp3_Activity_2 = Java.use("okhttp3.CertificatePinner");
            okhttp3_Activity_2.check.overload(
                "java.lang.String",
                "java.security.cert.Certificate"
            ).implementation = function(a, b) {
                send("  --> Bypassing OkHTTPv3 (cert): " + a);
                return;
            };
            send("[+] OkHTTPv3 (cert)");
        } catch (err) {
            send("[ ] OkHTTPv3 (cert)");
        }
        try {
            // Bypass OkHTTPv3 {3}
            const okhttp3_Activity_3 = Java.use("okhttp3.CertificatePinner");
            okhttp3_Activity_3.check.overload(
                "java.lang.String",
                "[Ljava.security.cert.Certificate;"
            ).implementation = function(a, b) {
                send("  --> Bypassing OkHTTPv3 (cert array): " + a);
                return;
            };
            send("[+] OkHTTPv3 (cert array)");
        } catch (err) {
            send("[ ] OkHTTPv3 (cert array)");
        }
        try {
            // Bypass OkHTTPv3 {4}
            const okhttp3_Activity_4 = Java.use("okhttp3.CertificatePinner");
            okhttp3_Activity_4["check$okhttp"].implementation = function(a, b) {
                send("  --> Bypassing OkHTTPv3 ($okhttp): " + a);
                return;
            };
            send("[+] OkHTTPv3 ($okhttp)");
        } catch (err) {
            send("[ ] OkHTTPv3 ($okhttp)");
        }

        // Trustkit (triple bypass)
        try {
            // Bypass Trustkit {1}
            const trustkit_Activity_1 = Java.use(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier"
            );
            trustkit_Activity_1.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSession"
            ).implementation = function(a, b) {
                send(
                    "  --> Bypassing Trustkit OkHostnameVerifier(SSLSession): " + a
                );
                return true;
            };
            send("[+] Trustkit OkHostnameVerifier(SSLSession)");
        } catch (err) {
            send("[ ] Trustkit OkHostnameVerifier(SSLSession)");
        }
        try {
            // Bypass Trustkit {2}
            const trustkit_Activity_2 = Java.use(
                "com.datatheorem.android.trustkit.pinning.OkHostnameVerifier"
            );
            trustkit_Activity_2.verify.overload(
                "java.lang.String",
                "java.security.cert.X509Certificate"
            ).implementation = function(a, b) {
                send("  --> Bypassing Trustkit OkHostnameVerifier(cert): " + a);
                return true;
            };
            send("[+] Trustkit OkHostnameVerifier(cert)");
        } catch (err) {
            send("[ ] Trustkit OkHostnameVerifier(cert)");
        }
        try {
            // Bypass Trustkit {3}
            const trustkit_PinningTrustManager = Java.use(
                "com.datatheorem.android.trustkit.pinning.PinningTrustManager"
            );
            trustkit_PinningTrustManager.checkServerTrusted.implementation =
                function() {
                    send("  --> Bypassing Trustkit PinningTrustManager");
                };
            send("[+] Trustkit PinningTrustManager");
        } catch (err) {
            send("[ ] Trustkit PinningTrustManager");
        }

        // Appcelerator Titanium
        try {
            const appcelerator_PinningTrustManager = Java.use(
                "appcelerator.https.PinningTrustManager"
            );
            appcelerator_PinningTrustManager.checkServerTrusted.implementation =
                function() {
                    send("  --> Bypassing Appcelerator PinningTrustManager");
                };
            send("[+] Appcelerator PinningTrustManager");
        } catch (err) {
            send("[ ] Appcelerator PinningTrustManager");
        }

        // OpenSSLSocketImpl Conscrypt
        try {
            const OpenSSLSocketImpl = Java.use(
                "com.android.org.conscrypt.OpenSSLSocketImpl"
            );
            OpenSSLSocketImpl.verifyCertificateChain.implementation = function(
                certRefs,
                JavaObject,
                authMethod
            ) {
                send("  --> Bypassing OpenSSLSocketImpl Conscrypt");
            };
            send("[+] OpenSSLSocketImpl Conscrypt");
        } catch (err) {
            send("[ ] OpenSSLSocketImpl Conscrypt");
        }

        // OpenSSLEngineSocketImpl Conscrypt
        try {
            const OpenSSLEngineSocketImpl_Activity = Java.use(
                "com.android.org.conscrypt.OpenSSLEngineSocketImpl"
            );
            OpenSSLEngineSocketImpl_Activity.verifyCertificateChain.overload(
                "[Ljava.lang.Long;",
                "java.lang.String"
            ).implementation = function(a, b) {
                send("  --> Bypassing OpenSSLEngineSocketImpl Conscrypt: " + b);
            };
            send("[+] OpenSSLEngineSocketImpl Conscrypt");
        } catch (err) {
            send("[ ] OpenSSLEngineSocketImpl Conscrypt");
        }

        // OpenSSLSocketImpl Apache Harmony
        try {
            const OpenSSLSocketImpl_Harmony = Java.use(
                "org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl"
            );
            OpenSSLSocketImpl_Harmony.verifyCertificateChain.implementation =
                function(asn1DerEncodedCertificateChain, authMethod) {
                    send("  --> Bypassing OpenSSLSocketImpl Apache Harmony");
                };
            send("[+] OpenSSLSocketImpl Apache Harmony");
        } catch (err) {
            send("[ ] OpenSSLSocketImpl Apache Harmony");
        }

        // PhoneGap sslCertificateChecker (https://github.com/EddyVerbruggen/SSLCertificateChecker-PhoneGap-Plugin)
        try {
            const phonegap_Activity = Java.use(
                "nl.xservices.plugins.sslCertificateChecker"
            );
            phonegap_Activity.execute.overload(
                "java.lang.String",
                "org.json.JSONArray",
                "org.apache.cordova.CallbackContext"
            ).implementation = function(a, b, c) {
                send("  --> Bypassing PhoneGap sslCertificateChecker: " + a);
                return true;
            };
            send("[+] PhoneGap sslCertificateChecker");
        } catch (err) {
            send("[ ] PhoneGap sslCertificateChecker");
        }

        // IBM MobileFirst pinTrustedCertificatePublicKey (double bypass)
        try {
            // Bypass IBM MobileFirst {1}
            const WLClient_Activity_1 = Java.use(
                "com.worklight.wlclient.api.WLClient"
            );
            WLClient_Activity_1.getInstance().pinTrustedCertificatePublicKey.overload(
                "java.lang.String"
            ).implementation = function(cert) {
                send(
                    "  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string): " +
                    cert
                );
                return;
            };
            send(
                "[+] IBM MobileFirst pinTrustedCertificatePublicKey (string)"
            );
        } catch (err) {
            send(
                "[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string)"
            );
        }
        try {
            // Bypass IBM MobileFirst {2}
            const WLClient_Activity_2 = Java.use(
                "com.worklight.wlclient.api.WLClient"
            );
            WLClient_Activity_2.getInstance().pinTrustedCertificatePublicKey.overload(
                "[Ljava.lang.String;"
            ).implementation = function(cert) {
                send(
                    "  --> Bypassing IBM MobileFirst pinTrustedCertificatePublicKey (string array): " +
                    cert
                );
                return;
            };
            send(
                "[+] IBM MobileFirst pinTrustedCertificatePublicKey (string array)"
            );
        } catch (err) {
            send(
                "[ ] IBM MobileFirst pinTrustedCertificatePublicKey (string array)"
            );
        }

        // IBM WorkLight (ancestor of MobileFirst) HostNameVerifierWithCertificatePinning (quadruple bypass)
        try {
            // Bypass IBM WorkLight {1}
            const worklight_Activity_1 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_1.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSocket"
            ).implementation = function(a, b) {
                send(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket): " +
                    a
                );
                return;
            };
            send(
                "[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)"
            );
        } catch (err) {
            send(
                "[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSocket)"
            );
        }
        try {
            // Bypass IBM WorkLight {2}
            const worklight_Activity_2 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_2.verify.overload(
                "java.lang.String",
                "java.security.cert.X509Certificate"
            ).implementation = function(a, b) {
                send(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (cert): " +
                    a
                );
                return;
            };
            send(
                "[+] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)"
            );
        } catch (err) {
            send(
                "[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (cert)"
            );
        }
        try {
            // Bypass IBM WorkLight {3}
            const worklight_Activity_3 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_3.verify.overload(
                "java.lang.String",
                "[Ljava.lang.String;",
                "[Ljava.lang.String;"
            ).implementation = function(a, b) {
                send(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (string string): " +
                    a
                );
                return;
            };
            send(
                "[+] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)"
            );
        } catch (err) {
            send(
                "[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (string string)"
            );
        }
        try {
            // Bypass IBM WorkLight {4}
            const worklight_Activity_4 = Java.use(
                "com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning"
            );
            worklight_Activity_4.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSession"
            ).implementation = function(a, b) {
                send(
                    "  --> Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession): " +
                    a
                );
                return true;
            };
            send(
                "[+] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)"
            );
        } catch (err) {
            send(
                "[ ] IBM WorkLight HostNameVerifierWithCertificatePinning (SSLSession)"
            );
        }

        // Conscrypt CertPinManager
        try {
            const conscrypt_CertPinManager_Activity = Java.use(
                "com.android.org.conscrypt.CertPinManager"
            );
            conscrypt_CertPinManager_Activity.isChainValid.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function(a, b) {
                send("  --> Bypassing Conscrypt CertPinManager: " + a);
                return true;
            };
            send("[+] Conscrypt CertPinManager");
        } catch (err) {
            send("[ ] Conscrypt CertPinManager");
        }

        // CWAC-Netsecurity (unofficial back-port pinner for Android<4.2) CertPinManager
        try {
            const cwac_CertPinManager_Activity = Java.use(
                "com.commonsware.cwac.netsecurity.conscrypt.CertPinManager"
            );
            cwac_CertPinManager_Activity.isChainValid.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function(a, b) {
                send("  --> Bypassing CWAC-Netsecurity CertPinManager: " + a);
                return true;
            };
            send("[+] CWAC-Netsecurity CertPinManager");
        } catch (err) {
            send("[ ] CWAC-Netsecurity CertPinManager");
        }

        // Worklight Androidgap WLCertificatePinningPlugin
        try {
            const androidgap_WLCertificatePinningPlugin_Activity = Java.use(
                "com.worklight.androidgap.plugin.WLCertificatePinningPlugin"
            );
            androidgap_WLCertificatePinningPlugin_Activity.execute.overload(
                "java.lang.String",
                "org.json.JSONArray",
                "org.apache.cordova.CallbackContext"
            ).implementation = function(a, b, c) {
                send(
                    "  --> Bypassing Worklight Androidgap WLCertificatePinningPlugin: " +
                    a
                );
                return true;
            };
            send("[+] Worklight Androidgap WLCertificatePinningPlugin");
        } catch (err) {
            send("[ ] Worklight Androidgap WLCertificatePinningPlugin");
        }

        // Netty FingerprintTrustManagerFactory
        try {
            const netty_FingerprintTrustManagerFactory = Java.use(
                "io.netty.handler.ssl.util.FingerprintTrustManagerFactory"
            );
            netty_FingerprintTrustManagerFactory.checkTrusted.implementation =
                function(type, chain) {
                    send("  --> Bypassing Netty FingerprintTrustManagerFactory");
                };
            send("[+] Netty FingerprintTrustManagerFactory");
        } catch (err) {
            send("[ ] Netty FingerprintTrustManagerFactory");
        }

        // Squareup CertificatePinner [OkHTTP<v3] (double bypass)
        try {
            // Bypass Squareup CertificatePinner {1}
            const Squareup_CertificatePinner_Activity_1 = Java.use(
                "com.squareup.okhttp.CertificatePinner"
            );
            Squareup_CertificatePinner_Activity_1.check.overload(
                "java.lang.String",
                "java.security.cert.Certificate"
            ).implementation = function(a, b) {
                send("  --> Bypassing Squareup CertificatePinner (cert): " + a);
                return;
            };
            send("[+] Squareup CertificatePinner (cert)");
        } catch (err) {
            send("[ ] Squareup CertificatePinner (cert)");
        }
        try {
            // Bypass Squareup CertificatePinner {2}
            const Squareup_CertificatePinner_Activity_2 = Java.use(
                "com.squareup.okhttp.CertificatePinner"
            );
            Squareup_CertificatePinner_Activity_2.check.overload(
                "java.lang.String",
                "java.util.List"
            ).implementation = function(a, b) {
                send("  --> Bypassing Squareup CertificatePinner (list): " + a);
                return;
            };
            send("[+] Squareup CertificatePinner (list)");
        } catch (err) {
            send("[ ] Squareup CertificatePinner (list)");
        }

        // Squareup OkHostnameVerifier [OkHTTP v3] (double bypass)
        try {
            // Bypass Squareup OkHostnameVerifier {1}
            const Squareup_OkHostnameVerifier_Activity_1 = Java.use(
                "com.squareup.okhttp.internal.tls.OkHostnameVerifier"
            );
            Squareup_OkHostnameVerifier_Activity_1.verify.overload(
                "java.lang.String",
                "java.security.cert.X509Certificate"
            ).implementation = function(a, b) {
                send("  --> Bypassing Squareup OkHostnameVerifier (cert): " + a);
                return true;
            };
            send("[+] Squareup OkHostnameVerifier (cert)");
        } catch (err) {
            send("[ ] Squareup OkHostnameVerifier (cert)");
        }
        try {
            // Bypass Squareup OkHostnameVerifier {2}
            const Squareup_OkHostnameVerifier_Activity_2 = Java.use(
                "com.squareup.okhttp.internal.tls.OkHostnameVerifier"
            );
            Squareup_OkHostnameVerifier_Activity_2.verify.overload(
                "java.lang.String",
                "javax.net.ssl.SSLSession"
            ).implementation = function(a, b) {
                send(
                    "  --> Bypassing Squareup OkHostnameVerifier (SSLSession): " + a
                );
                return true;
            };
            send("[+] Squareup OkHostnameVerifier (SSLSession)");
        } catch (err) {
            send("[ ] Squareup OkHostnameVerifier (SSLSession)");
        }

        // Android WebViewClient (double bypass)
        try {
            // Bypass WebViewClient {1} (deprecated from Android 6)
            const AndroidWebViewClient_Activity_1 = Java.use(
                "android.webkit.WebViewClient"
            );
            AndroidWebViewClient_Activity_1.onReceivedSslError.overload(
                "android.webkit.WebView",
                "android.webkit.SslErrorHandler",
                "android.net.http.SslError"
            ).implementation = function(obj1, obj2, obj3) {
                send("  --> Bypassing Android WebViewClient (SslErrorHandler)");
            };
            send("[+] Android WebViewClient (SslErrorHandler)");
        } catch (err) {
            send("[ ] Android WebViewClient (SslErrorHandler)");
        }
        try {
            // Bypass WebViewClient {2}
            const AndroidWebViewClient_Activity_2 = Java.use(
                "android.webkit.WebViewClient"
            );
            AndroidWebViewClient_Activity_2.onReceivedSslError.overload(
                "android.webkit.WebView",
                "android.webkit.WebResourceRequest",
                "android.webkit.WebResourceError"
            ).implementation = function(obj1, obj2, obj3) {
                send("  --> Bypassing Android WebViewClient (WebResourceError)");
            };
            send("[+] Android WebViewClient (WebResourceError)");
        } catch (err) {
            send("[ ] Android WebViewClient (WebResourceError)");
        }

        // Apache Cordova WebViewClient
        try {
            const CordovaWebViewClient_Activity = Java.use(
                "org.apache.cordova.CordovaWebViewClient"
            );
            CordovaWebViewClient_Activity.onReceivedSslError.overload(
                "android.webkit.WebView",
                "android.webkit.SslErrorHandler",
                "android.net.http.SslError"
            ).implementation = function(obj1, obj2, obj3) {
                send("  --> Bypassing Apache Cordova WebViewClient");
                obj3.proceed();
            };
        } catch (err) {
            send("[ ] Apache Cordova WebViewClient");
        }

        // Boye AbstractVerifier
        try {
            const boye_AbstractVerifier = Java.use(
                "ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier"
            );
            boye_AbstractVerifier.verify.implementation = function(host, ssl) {
                send("  --> Bypassing Boye AbstractVerifier: " + host);
            };
        } catch (err) {
            send("[ ] Boye AbstractVerifier");
        }

        // Appmattus
        try {
            const appmatus_Activity = Java.use(
                "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor"
            );
            appmatus_Activity["intercept"].implementation = function(a) {
                send("  --> Bypassing Appmattus (Transparency)");
                return a.proceed(a.request());
            };
            send("[+] Appmattus (CertificateTransparencyInterceptor)");
        } catch (err) {
            send("[ ] Appmattus (CertificateTransparencyInterceptor)");
        }

        try {
            const CertificateTransparencyTrustManager = Java.use(
                "com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager"
            );
            CertificateTransparencyTrustManager["checkServerTrusted"].overload(
                "[Ljava.security.cert.X509Certificate;",
                "java.lang.String"
            ).implementation = function(x509CertificateArr, str) {
                send(
                    "  --> Bypassing Appmattus (CertificateTransparencyTrustManager)"
                );
            };
            CertificateTransparencyTrustManager["checkServerTrusted"].overload(
                "[Ljava.security.cert.X509Certificate;",
                "java.lang.String",
                "java.lang.String"
            ).implementation = function(x509CertificateArr, str, str2) {
                send(
                    "  --> Bypassing Appmattus (CertificateTransparencyTrustManager)"
                );
                return Java.use("java.util.ArrayList").$new();
            };
            send("[+] Appmattus (CertificateTransparencyTrustManager)");
        } catch (err) {
            send("[ ] Appmattus (CertificateTransparencyTrustManager)");
        }

        send("Unpinning setup completed");
        send("---");
    });
}, 0);

Java.perform(function(){
	// 21.49
	// let setWebViewClient = Java.use("o.setWebViewClient");
	// setWebViewClient["read"].implementation = function (i, setinitialscale) {
		// send(`setWebViewClient.read is called: i=${i}, setinitialscale=${setinitialscale}`);
		// // this["read"](i, setinitialscale);
	// };

	// let setShadowLayer = Java.use("o.setShadowLayer");
	// setShadowLayer["$init"].implementation = function (str, str2) {
		// send(`setShadowLayer.$init is called: str=${str}, str2=${str2}`);
		// send(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()))
		// this["$init"](str, str2);
	// };

	// 22.11.2022060701
	// let getExpiryDate = Java.use("o.getExpiryDate");
	// getExpiryDate["IconCompatParcelizer"].implementation = function (setversion) {
		// send(`getExpiryDate.IconCompatParcelizer is called: setversion=${setversion}`);
		// // this["IconCompatParcelizer"](setversion);
	// };

	// let setVersion = Java.use("o.setVersion");
	// setVersion["RemoteActionCompatParcelizer"].implementation = function () {
		// send(`setVersion.RemoteActionCompatParcelizer is called`);
		// let result = this["RemoteActionCompatParcelizer"]();
		// send(`setVersion.RemoteActionCompatParcelizer result=${result}`);
		// return 1;
	// };

	// setVersion["MediaBrowserCompat$CustomActionResultReceiver"].implementation = function () {
		// send(`setVersion.MediaBrowserCompat$CustomActionResultReceiver is called`);
		// let result = this["MediaBrowserCompat$CustomActionResultReceiver"]();
		// send(`setVersion.MediaBrowserCompat$CustomActionResultReceiver result=${result}`);
		// return 1;
	// };

	// let setPorts = Java.use("o.setPorts");
	// setPorts["RemoteActionCompatParcelizer"].overload().implementation = function () {
		// send(`setPorts.RemoteActionCompatParcelizer is called`);
		// let result = this["RemoteActionCompatParcelizer"]();
		// send(`setPorts.RemoteActionCompatParcelizer result=${result}`);
		// return 1;
	// };

	// setPorts["write"].implementation = function () {
		// send(`setPorts.write is called`);
		// let result = this["write"]();
		// send(`setPorts.write result=${result}`);
		// return 1;
	// };

	// let setSpecialIns = Java.use("o.setSpecialIns");
	// setSpecialIns["read"].implementation = function () {
		// send(`setSpecialIns.read is called`);
		// let result = this["read"]();
		// send(`setSpecialIns.read result=${result}`);
		// return 1;
	// };
	// setSpecialIns["write"].implementation = function () {
		// send(`setSpecialIns.write is called`);
		// let result = this["write"]();
		// send(`setSpecialIns.write result=${result}`);
		// return 1;
	// };

	// let setDefault = Java.use("o.setDefault");
	// setDefault["RemoteActionCompatParcelizer"].implementation = function () {
		// send(`setDefault.RemoteActionCompatParcelizer is called`);
		// let result = this["RemoteActionCompatParcelizer"]();
		// send(`setDefault.RemoteActionCompatParcelizer result=${result}`);
		// return 1;
	// };

	// setDefault["MediaBrowserCompat$CustomActionResultReceiver"].implementation = function () {
		// send(`setDefault.MediaBrowserCompat$CustomActionResultReceiver is called`);
		// let result = this["MediaBrowserCompat$CustomActionResultReceiver"]();
		// send(`setDefault.MediaBrowserCompat$CustomActionResultReceiver result=${result}`);
		// return 1;
	// };

	// let setOptGroup = Java.use("o.setOptGroup");
	// setOptGroup["write"].implementation = function () {
		// send(`setOptGroup.write is called`);
		// let result = this["write"]();
		// send(`setOptGroup.write result=${result}`);
		// return 1;
	// };
	// setOptGroup["read"].implementation = function () {
		// send(`setOptGroup.read is called`);
		// let result = this["read"]();
		// send(`setOptGroup.read result=${result}`);
		// return 1;
	// };

	// let isDefault = Java.use("o.isDefault");
	// isDefault["MediaBrowserCompat$CustomActionResultReceiver"].implementation = function () {
		// send(`isDefault.MediaBrowserCompat$CustomActionResultReceiver is called`);
		// let result = this["MediaBrowserCompat$CustomActionResultReceiver"]();
		// send(`isDefault.MediaBrowserCompat$CustomActionResultReceiver result=${result}`);
		// return 1;
	// };
	// isDefault["write"].implementation = function () {
		// send(`isDefault.write is called`);
		// let result = this["write"]();
		// send(`isDefault.write result=${result}`);
		// return 1;
	// };

	// let setOptCredit = Java.use("o.setOptCredit");
	// setOptCredit["RemoteActionCompatParcelizer"].implementation = function () {
		// send(`setOptCredit.RemoteActionCompatParcelizer is called`);
		// let result = this["RemoteActionCompatParcelizer"]();
		// send(`setOptCredit.RemoteActionCompatParcelizer result=${result}`);
		// return 1;
	// };
	// setOptCredit["read"].implementation = function () {
		// send(`setOptCredit.read is called`);
		// let result = this["read"]();
		// send(`setOptCredit.read result=${result}`);
		// return 1;
	// };
});

setTimeout(function() {
	Java.perform(function() {
		send("started");

		var Log = Java.use("android.util.Log")
		var Exception = Java.use("java.lang.Exception")

		// KeyGenerator
		var keyGenerator = Java.use("javax.crypto.KeyGenerator");
		keyGenerator.generateKey.implementation = function () {
			send("[*] Generate symmetric key called. ");
			return this.generateKey();
		};

		keyGenerator.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] KeyGenerator.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		keyGenerator.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] KeyGenerator.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		keyGenerator.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] KeyGenerator.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		// KeyPairGenerator
		var keyPairGenerator = Java.use("java.security.KeyPairGenerator");
		keyPairGenerator.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] GetPairGenerator.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		keyPairGenerator.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] GetPairGenerator.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		keyPairGenerator.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] GetPairGenerator.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		// secret key spec
		var secretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
		secretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(keyb, cipher){
			var buffer = Java.array('byte', keyb);
			var resultStr = "";
			try{
				// for(var i = 0; i < buffer.length; ++i){
					// resultStr+= (String.fromCharCode(buffer[i]));
				// }
				resultStr = byteArrayToHex(buffer);
			}catch(e){
				resultStr = "0x";
				for(var i = 0; i < buffer.length; ++i){
					var nn = buffer[i];
					resultStr+= nn.toString(16);
				}
			}
			send("[*] SecretKeySpec.init called with key: " + resultStr + " using algorithm" + cipher + "\n");
			return secretKeySpec.$init.overload('[B', 'java.lang.String').call(this, keyb, cipher);
		}

		// MessageDigest
		var messageDigest = Java.use("java.security.MessageDigest");
		messageDigest.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] MessageDigest.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		messageDigest.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] MessageDigest.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		messageDigest.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] MessageDigest.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		messageDigest.digest.overload().implementation = function () {
			var ret =  messageDigest.digest.overload().call(this);
			var buffer = Java.array('byte', ret);
			var resultStr = "0x";
			for(var i = 0; i < 16; ++i){
				 var nn = buffer[i];
				 if (nn < 0)
				 {
				 	nn = 0xFFFFFFFF + nn + 1;
				 }
				 nn.toString(16).toUpperCase();
				 resultStr+= nn;
			}
			send("[*] MessageDigest.digest called with hash: " + resultStr + " using algorithm: " + this.getAlgorithm() + "\n");
			return ret;
		};

		/*
		messageDigest.digest.overload("[B").implementation = function (inp) {
			ret =  messageDigest.digest.overload("[B").call(this, inp);
			var buffer = Java.array('byte', ret);
			var resultStr = "0x";
			for(var i = 0; i < buffer.length; ++i){
				var nn = buffer[i];
				resultStr+= nn.toString(16);
			}
			send("[*] MessageDigest.digest called with hash: " + resultStr + " using algorithm: " + this.getAlgorithm() + "\n");
		};

		messageDigest.digest.overload("[B", "int", "int").implementation = function (inp, offset, len) {
			ret =  messageDigest.digest.overload("[B", "int", "int").call(this, inp, offset, len);
			var buffer = Java.array('byte', inp);
			var resultStr = "0x";
			for(var i = offset; i < ret; ++i){
				var nn = buffer[i];
				resultStr+= nn.toString(16);
			}
			send("[*] MessageDigest.digest called with hash: " + resultStr + " using algorithm: " + this.getAlgorithm() + "\n");
		};*/

		// secret key factory
		var secretKeyFactory = Java.use("javax.crypto.SecretKeyFactory");
		secretKeyFactory.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] SecretKeyFactory.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		secretKeyFactory.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] SecretKeyFactory.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		secretKeyFactory.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] SecretKeyFactory.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		// Signature
		var signature = Java.use("java.security.Signature");
		signature.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] Signature.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		signature.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] Signature.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		signature.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] Signature.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};


		// Cipher
		var cipher = Java.use("javax.crypto.Cipher");
		cipher.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] Cipher.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		cipher.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] Cipher.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		cipher.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] Cipher.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		cipher.doFinal.overload('[B').implementation = function (b) {
			send("Cipher.doFinal called by " + Log.getStackTraceString(Exception.$new()));
			return cipher.doFinal.overload("[B").call(this, b);
		};


		// MAC

		var mac = Java.use("javax.crypto.Mac");
		mac.getInstance.overload('java.lang.String').implementation = function (var0) {
			send("[*] Mac.getInstance called with algorithm: " + var0 + "\n");
			return this.getInstance(var0);
		};

		mac.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (var0, var1) {
			send("[*] Mac.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};

		mac.getInstance.overload('java.lang.String', 'java.security.Provider').implementation = function (var0, var1) {
			send("[*] Mac.getInstance called with algorithm: " + var0 + " and provider: " + var1 + "\n");
			return this.getInstance(var0, var1);
		};
		mac.doFinal.overload('[B').implementation = function(data){
            send("---------enter SecretKeySpec init---------");
            send("KEY: " + bin2hex(data) + " | " + bin2ascii(data));
            let ret = this.doFinal(data);
            send(data, ret);
            return ret;
        }


		/** KeyGenParameterSpec **/

		//decrypt = 2
		// encrypt = 1
		// decrypt | encrypt = 3
		// sign = 4
		// verify = 8
		var useKeyGen = Java.use("android.security.keystore.KeyGenParameterSpec$Builder");
		useKeyGen.$init.overload("java.lang.String", "int").implementation = function(keyStoreAlias, purpose){
			var purposeStr = "Purpose = " + purpose;
			if (purpose == 2)
				purposeStr = "decrypt";
			else if (purpose == 1)
				purposeStr = "encrypt";
			else if (purpose == 3)
				purposeStr = "decrypt|encrypt";
			else if (purpose == 4)
				purposeStr = "sign";
			else if (purpose == 8)
				purposeStr = "verify";

			send("KeyGenParameterSpec.Builder(" + keyStoreAlias + ", " + purposeStr + ")");

			return useKeyGen.$init.overload("java.lang.String", "int").call(this, keyStoreAlias, purpose);
		}

		useKeyGen.setBlockModes.implementation = function(modes){
			send("KeyGenParameterSpec.Builder.setBlockModes('"+ modes.toString() +"')");
			return useKeyGen.setBlockModes.call(this, modes);
		}

		useKeyGen.setDigests.implementation = function(digests){
			send("KeyGenParameterSpec.Builder.setDigests('"+ digests.toString() +"')");
			return useKeyGen.setDigests.call(this, digests);
		}

		useKeyGen.setKeySize.implementation = function(keySize){
			send("KeyGenParameterSpec.Builder.setKeySize("+ keySize +")");
			return useKeyGen.setKeySize.call(this, keySize);
		}

		useKeyGen.setEncryptionPaddings.implementation = function(paddings){
			send("KeyGenParameterSpec.Builder.setEncryptionPaddings('"+ paddings.toString() +"')");
			return useKeyGen.setEncryptionPaddings.call(this, paddings);
		}

		useKeyGen.setSignaturePaddings.implementation = function(paddings){
			send("KeyGenParameterSpec.Builder.setSignaturePaddings('"+ paddings.toString() +"')");
			return useKeyGen.setSignaturePaddings.call(this, paddings);
		}

		useKeyGen.setAlgorithmParameterSpec.implementation = function(spec){
			send("KeyGenParameterSpec.Builder.setAlgorithmParameterSpec('"+ spec.toString() +"')");
			return useKeyGen.setAlgorithmParameterSpec.call(this, spec);
		}

		useKeyGen.build.implementation = function(){
			send("KeyGenParameterSpec.Builder.build()");
			return useKeyGen.build.call(this);
		}

		// IvParameterSpec
		var ivSpec = Java.use("javax.crypto.spec.IvParameterSpec");
		ivSpec.$init.overload("[B").implementation = function(ivBytes){
			var buffer = Java.array('byte', ivBytes);
			var resultStr = "";
			try{
				for(var i = 0; i < buffer.length; ++i){
					resultStr+= (String.fromCharCode(buffer[i]));
				}
			}catch(e){
				resultStr = "0x";
				for(var i = 0; i < buffer.length; ++i){
					var nn = buffer[i];
					resultStr+= nn.toString(16);
				}
			}
			send("IvParameterSpec.init(" + resultStr + ")");
			return ivSpec.$init.overload("[B").call(this, ivBytes);
		}

		ivSpec.$init.overload("[B", "int", "int").implementation = function(ivBytes, offset, len){
			var buffer = Java.array('byte', ivBytes);
			var resultStr = "";
			try{
				for(var i = offset; i < len; ++i){
					resultStr+= (String.fromCharCode(buffer[i]));
				}
			}catch(e){
				resultStr = "0x";
				for(var i = offset; i < len; ++i){
					var nn = buffer[i];
					resultStr+= nn.toString(16);
				}
			}
			send("IvParameterSpec.init(" + resultStr + ")");
			return ivSpec.$init.overload("[B", "int", "int").call(this, ivBytes, offset, len);
		}

		Java.perform(function() {
			Java.use('javax.crypto.spec.SecretKeySpec').$init.overload('[B', 'java.lang.String').implementation = function(key, spec) {
				send("KEY: " + bin2hex(key) + " | " + bin2ascii(key));
				return this.$init(key, spec);
			};

			Java.use('javax.crypto.Cipher')['getInstance'].overload('java.lang.String').implementation = function(spec) {
				send("CIPHER: " + spec);
				return this.getInstance(spec);
			};

			Java.use('javax.crypto.Cipher')['doFinal'].overload('[B').implementation = function(data) {
				send("Gotcha!");
				send(bin2ascii(data));
				return this.doFinal(data);
			};
		});
	});
}, 0);

function byteArrayToHex(byteArray) {
    return Array.from(byteArray)
        .map(byte => ('0' + (byte & 0xff).toString(16)).slice(-2))
        .join('');
}

function bin2ascii(array) {
    var result = [];

    for (var i = 0; i < array.length; ++i) {
        result.push(String.fromCharCode( // hex2ascii part
            parseInt(
                ('0' + (array[i] & 0xFF).toString(16)).slice(-2), // binary2hex part
                16
            )
        ));
    }
    return result.join('');
}

function bin2hex(array, length) {
    var result = "";

    length = length || array.length;

    for (var i = 0; i < length; ++i) {
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    }
    return result;
}