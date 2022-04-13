大家都知道android系统的Zygote进程是所有的android进程的父进程，包括SystemServer和各种应用进程都是通过Zygote进程fork出来的。Zygote（孵化）进程相当于是android系统的根进程，后面所有的进程都是通过这个进程fork出来的，而Zygote进程则是通过linux系统的init进程启动的，也就是说，android系统中各种进程的启动方式

init进程  --> Zygote进程 --> SystemServer进程 -->各种应用进程

- init进程：linux的根进程，android系统是基于linux系统的，因此可以算作是整个android操作系统的第一个进程；init进程是Linux内核启动完成后在用户空间启动的第一个进程，主要负责初始化工作、启动属性服务、解析init.rc文件并启动Zygote进程。

- Zygote进程：android系统的根进程，是一个进程孵化器。主要作用：负责创建虚拟机实例、应用程序进程、系统服务进程SystemServer。他通过fork（复制进程）的方式创建子进程，子进程能继承父进程的系统资源如常用类、注册的JNI函数、主题资源、共享库等。

- SystemServer进程：主要是在这个进程中启动系统的各项服务，比如ActivityManagerService，PackageManagerService，WindowManagerService服务等等；

- 各种应用进程：启动自己编写的客户端应用时，一般都是重新启动一个应用进程，有自己的虚拟机与运行环境；

### Zygote进程启动流程

init进程会解析配置文件init.rc，来启动一些需要在开机时就启动的系统进程，如Zygote进程、ServiceManager进程等。

```
static void LoadBootScripts(ActionManager& action_manager, ServiceList& service_list) {
    Parser parser = CreateParser(action_manager, service_list);

    std::string bootscript = GetProperty("ro.boot.init_rc", "");
    if (bootscript.empty()) {
        parser.ParseConfig("/system/etc/init/hw/init.rc");//解析init.rc
        if (!parser.ParseConfig("/system/etc/init")) {
            late_import_paths.emplace_back("/system/etc/init");
        }
        // late_import is available only in Q and earlier release. As we don't
        // have system_ext in those versions, skip late_import for system_ext.
        parser.ParseConfig("/system_ext/etc/init");
        if (!parser.ParseConfig("/product/etc/init")) {
            late_import_paths.emplace_back("/product/etc/init");
        }
        if (!parser.ParseConfig("/odm/etc/init")) {
            late_import_paths.emplace_back("/odm/etc/init");
        }
        if (!parser.ParseConfig("/vendor/etc/init")) {
            late_import_paths.emplace_back("/vendor/etc/init");
        }
    } else {
        parser.ParseConfig(bootscript);
    }
}
```

init.rc是由Android初始化语言编写的脚本配置。由于Android 5.0开始支持了64bit程序，在init.rc里改成了通过${ro.zygote}的值来引入Zygote相关的配置
/system/core/rootdir/init.rc

```
import /system/etc/init/hw/init.${ro.zygote}.rc
...
# It is recommended to put unnecessary data/ initialization from post-fs-data
# to start-zygote in device's init.rc to unblock zygote start.
on zygote-start && property:ro.crypto.state=unencrypted
    # A/B update verifier that marks a successful boot.
    exec_start update_verifier_nonencrypted
    start statsd
    start netd
    start zygote
    start zygote_secondary
```
- 调用start zygote会执行init.${ro.zygote}.rc文件，${ro.zygote}的取值有4种，在init.rc的同级目录/system/core/rootdir下，可以看到4个Zygote相关的配置文件，表示系统所支持程序的bit位数：

1.init.zygote32.rc，Zygote进程的执行程序路径为/system/bin/app_process

2.init.zygote64.rc，Zygote进程的执行程序路径为/system/bin/app_process64

3.init.zygote32_64.rc，会启动两个Zygote进程，有两个执行程序，32为主模式

4.init.zygote64_32.rc，会启动两个Zygote进程，有两个执行程序，64为主模式

下面我们看一下init.zygote32.rc

```
service zygote /system/bin/app_process -Xzygote /system/bin --zygote --start-system-server
        class main
        priority -20
        user root
        group root readproc reserved_disk
        socket zygote stream 660 root system
...

```
第一行中，service表示Zygote进程以服务的形式来启动，zygote则是进程的名字，/system/bin/app_process是执行程序的路径，后面几项则是传给执行程序的参数，其中--start-system-server表示在Zygote进程启动后需要启动SystemServer进程。
然后是最后一行，Zygote进程是使用socket来进行跨进程通信的，所以会创建一个名为zygote的socket，660表示访问权限rw-rw----，表示文件拥有者和同一群组用户具有读写权限。

之后会执行到/frameworks/base/cmds/app_process/app_main.cpp 源码文件中的 main 方法

```
     if (zygote) {
        runtime.start("com.android.internal.os.ZygoteInit", args, zygote);//启动Zygote，进入ZygoteInit.main函数
     } else if (className) {
        runtime.start("com.android.internal.os.RuntimeInit", args, zygote);
     } else {
        fprintf(stderr, "Error: no class name or --zygote supplied.\n");
        app_usage();
        LOG_ALWAYS_FATAL("app_process: no class name or --zygote supplied.");
    }

```
再看一下AndroidRuntime.cpp的start方法
frameworks/base/core/jni/AndroidRuntime.cpp

```
void AndroidRuntime::start(const char* className, const Vector<String8>& options, bool zygote)
{
    ALOGD(">>>>>> START %s uid %d <<<<<<\n",
            className != NULL ? className : "(unknown)", getuid());

    static const String8 startSystemServer("start-system-server");
    // Whether this is the primary zygote, meaning the zygote which will fork system server.
    bool primary_zygote = false;

    /*
     * 'startSystemServer == true' means runtime is obsolete and not run from
     * init.rc anymore, so we print out the boot start event here.
     */
    for (size_t i = 0; i < options.size(); ++i) {
        if (options[i] == startSystemServer) {
            primary_zygote = true;
           /* track our progress through the boot sequence */
           const int LOG_BOOT_PROGRESS_START = 3000;
           LOG_EVENT_LONG(LOG_BOOT_PROGRESS_START,  ns2ms(systemTime(SYSTEM_TIME_MONOTONIC)));
        }
    }

    const char* rootDir = getenv("ANDROID_ROOT");
    if (rootDir == NULL) {
        rootDir = "/system";
        if (!hasDir("/system")) {
            LOG_FATAL("No root directory specified, and /system does not exist.");
            return;
        }
        setenv("ANDROID_ROOT", rootDir, 1);
    }

    const char* artRootDir = getenv("ANDROID_ART_ROOT");
    if (artRootDir == NULL) {
        LOG_FATAL("No ART directory specified with ANDROID_ART_ROOT environment variable.");
        return;
    }

    const char* i18nRootDir = getenv("ANDROID_I18N_ROOT");
    if (i18nRootDir == NULL) {
        LOG_FATAL("No runtime directory specified with ANDROID_I18N_ROOT environment variable.");
        return;
    }

    const char* tzdataRootDir = getenv("ANDROID_TZDATA_ROOT");
    if (tzdataRootDir == NULL) {
        LOG_FATAL("No tz data directory specified with ANDROID_TZDATA_ROOT environment variable.");
        return;
    }

    //const char* kernelHack = getenv("LD_ASSUME_KERNEL");
    //ALOGD("Found LD_ASSUME_KERNEL='%s'\n", kernelHack);

    /* start the virtual machine */
    JniInvocation jni_invocation;
    jni_invocation.Init(NULL);//加载libart.so 
    JNIEnv* env;
    if (startVm(&mJavaVM, &env, zygote, primary_zygote) != 0) {
        return;
    }
    onVmCreated(env);

    /*
     * Register android functions.
     */
    if (startReg(env) < 0) {
        ALOGE("Unable to register all android natives\n");
        return;
    }

    /*
     * We want to call main() with a String array with arguments in it.
     * At present we have two arguments, the class name and an option string.
     * Create an array to hold them.
     */
    jclass stringClass;
    jobjectArray strArray;
    jstring classNameStr;

    stringClass = env->FindClass("java/lang/String");
    assert(stringClass != NULL);
    strArray = env->NewObjectArray(options.size() + 1, stringClass, NULL);
    assert(strArray != NULL);
    classNameStr = env->NewStringUTF(className);
    assert(classNameStr != NULL);
    env->SetObjectArrayElement(strArray, 0, classNameStr);

    for (size_t i = 0; i < options.size(); ++i) {
        jstring optionsStr = env->NewStringUTF(options.itemAt(i).string());
        assert(optionsStr != NULL);
        env->SetObjectArrayElement(strArray, i + 1, optionsStr);
    }

    /*
     * Start VM.  This thread becomes the main thread of the VM, and will
     * not return until the VM exits.
     */
    char* slashClassName = toSlashClassName(className != NULL ? className : "");
    jclass startClass = env->FindClass(slashClassName);
    if (startClass == NULL) {
        ALOGE("JavaVM unable to locate class '%s'\n", slashClassName);
        /* keep going */
    } else {
        jmethodID startMeth = env->GetStaticMethodID(startClass, "main",
            "([Ljava/lang/String;)V");
        if (startMeth == NULL) {
            ALOGE("JavaVM unable to find main() in '%s'\n", className);
            /* keep going */
        } else {
            env->CallStaticVoidMethod(startClass, startMeth, strArray);

#if 0
            if (env->ExceptionCheck())
                threadExitUncaughtException(env);
#endif
        }
    }
    free(slashClassName);

    ALOGD("Shutting down VM\n");
    if (mJavaVM->DetachCurrentThread() != JNI_OK)
        ALOGW("Warning: unable to detach main thread\n");
    if (mJavaVM->DestroyJavaVM() != 0)
        ALOGW("Warning: VM did not shut down cleanly\n");
}
```
1.加载libart.so，否则不能启动虚拟机；2.启动虚拟机；3.加载注册JNI方法；4.根据传递给start方法的第一个参数，去寻找ZygoteInit类，找到类之后，找到该类的main方法，然后调用，在这之后就进入了Java的世界。start方法的第一个参数为"com.android.internal.os.ZygoteInit"，然后通过FindClass方法找到ZygoteInit类，然后再调用相应的main方法进入到Java世界。


### SystemServer进程启动流程

frameworks/base/core/java/com/android/internal/os/ZygoteInit.java

```
public static void main(String argv[]) {
        ZygoteServer zygoteServer = null;

        // Mark zygote start. This ensures that thread creation will throw
        // an error.
        ZygoteHooks.startZygoteNoThreadCreation();

        // Zygote goes into its own process group.
        try {
            Os.setpgid(0, 0);
        } catch (ErrnoException ex) {
            throw new RuntimeException("Failed to setpgid(0,0)", ex);
        }

        Runnable caller;
        try {
            // Store now for StatsLogging later.
            final long startTime = SystemClock.elapsedRealtime();
            final boolean isRuntimeRestarted = "1".equals(
                    SystemProperties.get("sys.boot_completed"));

            String bootTimeTag = Process.is64Bit() ? "Zygote64Timing" : "Zygote32Timing";
            TimingsTraceLog bootTimingsTraceLog = new TimingsTraceLog(bootTimeTag,
                    Trace.TRACE_TAG_DALVIK);
            bootTimingsTraceLog.traceBegin("ZygoteInit");
            RuntimeInit.preForkInit();

            boolean startSystemServer = false;
            String zygoteSocketName = "zygote";
            String abiList = null;
            boolean enableLazyPreload = false;
            for (int i = 1; i < argv.length; i++) {
                if ("start-system-server".equals(argv[i])) {
                    startSystemServer = true;
                } else if ("--enable-lazy-preload".equals(argv[i])) {
                    enableLazyPreload = true;
                } else if (argv[i].startsWith(ABI_LIST_ARG)) {
                    abiList = argv[i].substring(ABI_LIST_ARG.length());
                } else if (argv[i].startsWith(SOCKET_NAME_ARG)) {
                    zygoteSocketName = argv[i].substring(SOCKET_NAME_ARG.length());
                } else {
                    throw new RuntimeException("Unknown command line argument: " + argv[i]);
                }
            }

            final boolean isPrimaryZygote = zygoteSocketName.equals(Zygote.PRIMARY_SOCKET_NAME);
            if (!isRuntimeRestarted) {
                if (isPrimaryZygote) {
                    FrameworkStatsLog.write(FrameworkStatsLog.BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
                            BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__ZYGOTE_INIT_START,
                            startTime);
                } else if (zygoteSocketName.equals(Zygote.SECONDARY_SOCKET_NAME)) {
                    FrameworkStatsLog.write(FrameworkStatsLog.BOOT_TIME_EVENT_ELAPSED_TIME_REPORTED,
                            BOOT_TIME_EVENT_ELAPSED_TIME__EVENT__SECONDARY_ZYGOTE_INIT_START,
                            startTime);
                }
            }

            if (abiList == null) {
                throw new RuntimeException("No ABI list supplied.");
            }

            // In some configurations, we avoid preloading resources and classes eagerly.
            // In such cases, we will preload things prior to our first fork.
            if (!enableLazyPreload) {
                bootTimingsTraceLog.traceBegin("ZygotePreload");
                EventLog.writeEvent(LOG_BOOT_PROGRESS_PRELOAD_START,
                        SystemClock.uptimeMillis());
                preload(bootTimingsTraceLog);
                EventLog.writeEvent(LOG_BOOT_PROGRESS_PRELOAD_END,
                        SystemClock.uptimeMillis());
                bootTimingsTraceLog.traceEnd(); // ZygotePreload
            }

            // Do an initial gc to clean up after startup
            bootTimingsTraceLog.traceBegin("PostZygoteInitGC");
            gcAndFinalize();
            bootTimingsTraceLog.traceEnd(); // PostZygoteInitGC

            bootTimingsTraceLog.traceEnd(); // ZygoteInit

            Zygote.initNativeState(isPrimaryZygote);

            ZygoteHooks.stopZygoteNoThreadCreation();

            zygoteServer = new ZygoteServer(isPrimaryZygote);

            if (startSystemServer) {
                Runnable r = forkSystemServer(abiList, zygoteSocketName, zygoteServer);

                // {@code r == null} in the parent (zygote) process, and {@code r != null} in the
                // child (system_server) process.
                if (r != null) {
                    r.run();
                    return;
                }
            }

            Log.i(TAG, "Accepting command socket connections");

            // The select loop returns early in the child process after a fork and
            // loops forever in the zygote.
            caller = zygoteServer.runSelectLoop(abiList);
        } catch (Throwable ex) {
            Log.e(TAG, "System zygote died with exception", ex);
            throw ex;
        } finally {
            if (zygoteServer != null) {
                zygoteServer.closeServerSocket();
            }
        }

        // We're in the child process and have exited the select loop. Proceed to execute the
        // command.
        if (caller != null) {
            caller.run();
        }
    }
```

- 通过forkSystemServer方法启动SystemServer

```
private static Runnable forkSystemServer(String abiList, String socketName,
            ZygoteServer zygoteServer) {
        long capabilities = posixCapabilitiesAsBits(
                OsConstants.CAP_IPC_LOCK,
                OsConstants.CAP_KILL,
                OsConstants.CAP_NET_ADMIN,
                OsConstants.CAP_NET_BIND_SERVICE,
                OsConstants.CAP_NET_BROADCAST,
                OsConstants.CAP_NET_RAW,
                OsConstants.CAP_SYS_MODULE,
                OsConstants.CAP_SYS_NICE,
                OsConstants.CAP_SYS_PTRACE,
                OsConstants.CAP_SYS_TIME,
                OsConstants.CAP_SYS_TTY_CONFIG,
                OsConstants.CAP_WAKE_ALARM,
                OsConstants.CAP_BLOCK_SUSPEND
        );
        /* Containers run without some capabilities, so drop any caps that are not available. */
        StructCapUserHeader header = new StructCapUserHeader(
                OsConstants._LINUX_CAPABILITY_VERSION_3, 0);
        StructCapUserData[] data;
        try {
            data = Os.capget(header);
        } catch (ErrnoException ex) {
            throw new RuntimeException("Failed to capget()", ex);
        }
        capabilities &= ((long) data[0].effective) | (((long) data[1].effective) << 32);

        /* Hardcoded command line to start the system server */
        String args[] = {
                "--setuid=1000",
                "--setgid=1000",
                "--setgroups=1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1018,1021,1023,"
                        + "1024,1032,1065,3001,3002,3003,3006,3007,3009,3010,3011",
                "--capabilities=" + capabilities + "," + capabilities,
                "--nice-name=system_server",
                "--runtime-args",
                "--target-sdk-version=" + VMRuntime.SDK_VERSION_CUR_DEVELOPMENT,
                "com.android.server.SystemServer",
        };
        ZygoteArguments parsedArgs = null;

        int pid;

        try {
            parsedArgs = new ZygoteArguments(args);
            Zygote.applyDebuggerSystemProperty(parsedArgs);
            Zygote.applyInvokeWithSystemProperty(parsedArgs);

            if (Zygote.nativeSupportsTaggedPointers()) {
                /* Enable pointer tagging in the system server. Hardware support for this is present
                 * in all ARMv8 CPUs. */
                parsedArgs.mRuntimeFlags |= Zygote.MEMORY_TAG_LEVEL_TBI;
            }

            /* Enable gwp-asan on the system server with a small probability. This is the same
             * policy as applied to native processes and system apps. */
            parsedArgs.mRuntimeFlags |= Zygote.GWP_ASAN_LEVEL_LOTTERY;

            if (shouldProfileSystemServer()) {
                parsedArgs.mRuntimeFlags |= Zygote.PROFILE_SYSTEM_SERVER;
            }

            /* Request to fork the system server process */
            pid = Zygote.forkSystemServer( //注释1
                    parsedArgs.mUid, parsedArgs.mGid,
                    parsedArgs.mGids,
                    parsedArgs.mRuntimeFlags,
                    null,
                    parsedArgs.mPermittedCapabilities,
                    parsedArgs.mEffectiveCapabilities);
        } catch (IllegalArgumentException ex) {
            throw new RuntimeException(ex);
        }

        /* For child process */
        if (pid == 0) {
            if (hasSecondZygote(abiList)) {//注释2
                waitForSecondaryZygote(socketName);
            }

            zygoteServer.closeServerSocket();//注释3
            return handleSystemServerProcess(parsedArgs);//注释4
        }

        return null;
    }
```

- forkSystemServer()方法主要执行了以下几个任务：

1.准备 system server 启动的参数，注释1之前的代码。

2.调用 Zygote forkSystemServer() 出 system server 进程，注释1处。

3.如果系统初始化了 SecondZygote，则通过 SecondZygote 建立连接，注释2处。

4.关闭从 zygote 进程复制的 socket，因为 system server 通过 binder 与其它进程通信(zygote 进程除外)，注释3处。

5.最后调用 handleSystemServerProcess() 处理 system server 进程初始化工作。注释4处。

```
/**
     * Finish remaining work for the newly forked system server process.
     */
    private static Runnable handleSystemServerProcess(ZygoteArguments parsedArgs) {
        // set umask to 0077 so new files and directories will default to owner-only permissions.
        Os.umask(S_IRWXG | S_IRWXO);

        if (parsedArgs.mNiceName != null) {
            Process.setArgV0(parsedArgs.mNiceName);
        }

        final String systemServerClasspath = Os.getenv("SYSTEMSERVERCLASSPATH");
        if (systemServerClasspath != null) {
            performSystemServerDexOpt(systemServerClasspath);
            // Capturing profiles is only supported for debug or eng builds since selinux normally
            // prevents it.
            if (shouldProfileSystemServer() && (Build.IS_USERDEBUG || Build.IS_ENG)) {
                try {
                    Log.d(TAG, "Preparing system server profile");
                    prepareSystemServerProfile(systemServerClasspath);
                } catch (Exception e) {
                    Log.wtf(TAG, "Failed to set up system server profile", e);
                }
            }
        }

        if (parsedArgs.mInvokeWith != null) {
            String[] args = parsedArgs.mRemainingArgs;
            // If we have a non-null system server class path, we'll have to duplicate the
            // existing arguments and append the classpath to it. ART will handle the classpath
            // correctly when we exec a new process.
            if (systemServerClasspath != null) {
                String[] amendedArgs = new String[args.length + 2];
                amendedArgs[0] = "-cp";
                amendedArgs[1] = systemServerClasspath;
                System.arraycopy(args, 0, amendedArgs, 2, args.length);
                args = amendedArgs;
            }

            WrapperInit.execApplication(parsedArgs.mInvokeWith,
                    parsedArgs.mNiceName, parsedArgs.mTargetSdkVersion,
                    VMRuntime.getCurrentInstructionSet(), null, args);

            throw new IllegalStateException("Unexpected return from WrapperInit.execApplication");
        } else {
            ClassLoader cl = null;
            if (systemServerClasspath != null) {
                cl = createPathClassLoader(systemServerClasspath, parsedArgs.mTargetSdkVersion);

                Thread.currentThread().setContextClassLoader(cl);
            }

            /*
             * Pass the remaining arguments to SystemServer.
             */
            return ZygoteInit.zygoteInit(parsedArgs.mTargetSdkVersion,
                    parsedArgs.mDisabledCompatChanges,
                    parsedArgs.mRemainingArgs, cl);
        }

        /* should never reach here */
    }
```

handleSystemServerProcess() 方法中首先会对 SystemServerClass 做dex优化，然后根据 parsedArgs.mInvokeWith 是否为空走不同的分支，跟踪代码可知 parsedArgs.mInvokeWith == null，即最后执行到了 ZygoteInit.zygoteInit()。


```
private static boolean startSystemServer(String abiList, String socketName)
            throws MethodAndArgsCaller, RuntimeException {
        long capabilities = posixCapabilitiesAsBits(
            OsConstants.CAP_BLOCK_SUSPEND,
            OsConstants.CAP_KILL,
            OsConstants.CAP_NET_ADMIN,
            OsConstants.CAP_NET_BIND_SERVICE,
            OsConstants.CAP_NET_BROADCAST,
            OsConstants.CAP_NET_RAW,
            OsConstants.CAP_SYS_MODULE,
            OsConstants.CAP_SYS_NICE,
            OsConstants.CAP_SYS_RESOURCE,
            OsConstants.CAP_SYS_TIME,
            OsConstants.CAP_SYS_TTY_CONFIG
        );
        /* Hardcoded command line to start the system server */
        String args[] = {
            "--setuid=1000",
            "--setgid=1000",
            "--setgroups=1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1018,1021,1032,3001,3002,3003,3006,3007",
            "--capabilities=" + capabilities + "," + capabilities,
            "--nice-name=system_server",
            "--runtime-args",
            "com.android.server.SystemServer",
        };
        ZygoteConnection.Arguments parsedArgs = null;

        int pid;

        try {
            parsedArgs = new ZygoteConnection.Arguments(args);
            ZygoteConnection.applyDebuggerSystemProperty(parsedArgs);
            ZygoteConnection.applyInvokeWithSystemProperty(parsedArgs);

            /* Request to fork the system server process */
            pid = Zygote.forkSystemServer(
                    parsedArgs.uid, parsedArgs.gid,
                    parsedArgs.gids,
                    parsedArgs.debugFlags,
                    null,
                    parsedArgs.permittedCapabilities,
                    parsedArgs.effectiveCapabilities);
        } catch (IllegalArgumentException ex) {
            throw new RuntimeException(ex);
        }

        /* For child process */
        if (pid == 0) {
            if (hasSecondZygote(abiList)) {
                waitForSecondaryZygote(socketName);
            }

            handleSystemServerProcess(parsedArgs);
        }

        return true;
    }
```
可以看到这段逻辑的执行逻辑就是通过Zygote fork出SystemServer进程。

总结：
Zygote进程mian方法主要执行逻辑：

- 初始化DDMS；

- 注册Zygote进程的socket通讯；

- 初始化Zygote中的各种类，资源文件，OpenGL，类库，Text资源等等；

- 初始化完成之后fork出SystemServer进程；

- fork出SystemServer进程之后，关闭socket连接；

### 面试问题总结：

1.init进程是什么？

Android是基于linux系统的，手机开机之后，linux内核进行加载。加载完成之后会启动init进程。

init进程会启动ServiceManager，孵化一些守护进程，并解析init.rc孵化Zygote进程。

2.Zygote进程是什么？

所有的App进程都是由Zygote进程fork生成的，包括SystemServer进程。Zygote初始化后，会注册一个等待接受消息的socket，OS层会采用socket进行IPC通信。

3.为什么是Zygote来孵化进程，而不是新建进程呢？

每个应用程序都是运行在各自的Dalvik虚拟机中，应用程序每次运行都要重新初始化和启动虚拟机，这个过程会耗费很长时间。Zygote会把已经运行的虚拟机的代码和内存信息共享，起到一个预加载资源和类的作用，从而缩短启动时间。

4.为什么SystemServer进程与Zygote进程通讯采用Socket而不是Binder？

Binder通讯是需要多线程操作的，代理对象对Binder的调用是在Binder线程，需要再通过Handler调用主线程来操作。

比如AMS与应用进程通讯，AMS的本地代理IApplicationThread通过调用ScheduleLaunchActivity，调用到的应用进程ApplicationThread的ScheduleLaunchActivity是在Binder线程，需要再把参数封装为一个ActivityClientRecord，sendMessage发送给H类（主线程Handler，ActivityThread内部类

可能父进程（如zygote）binder线程有锁，然后子进程的主线程一直在等其子线程(从父进程拷贝过来的子进程)的资源，但是其实父进程的子进程并没有被拷贝过来，造成死锁，所以fork不允许存在多线程。而非常巧的是Binder通讯偏偏就是多线程，所以干脆父进程（Zgote）这个时候就不使用binder线程。

另外对android源码解析方法感兴趣的可参考我的：
<br><a href="http://blog.csdn.net/qq_23547831/article/details/50634435"> android源码解析之（一）-->android项目构建过程</a>
<br><a href="http://blog.csdn.net/qq_23547831/article/details/50751687">android源码解析之（二）-->异步消息机制</a>
<br><a href="http://blog.csdn.net/qq_23547831/article/details/50803849">android源码解析之（三）-->异步任务AsyncTask</a>
<br><a href="http://blog.csdn.net/qq_23547831/article/details/50936584">android源码解析之（四）-->HandlerThread</a>
<br><a href="http://blog.csdn.net/qq_23547831/article/details/50958757">android源码解析之（五）-->IntentService</a>
<br><a href="http://blog.csdn.net/qq_23547831/article/details/50963006">android源码解析之（六）-->Log</a>
<br><a href="http://blog.csdn.net/qq_23547831/article/details/50971968">android源码解析之（七）-->LruCache</a>
