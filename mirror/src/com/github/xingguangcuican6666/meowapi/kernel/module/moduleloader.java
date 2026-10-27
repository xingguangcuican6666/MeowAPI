package com.github.xingguangcuican6666.meowapi.kernel.module;

import com.github.xingguangcuican6666.meowapi.kernel.security.scontext;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class moduleloader {

    private static final class PluginClassLoader extends URLClassLoader {
        PluginClassLoader(URL[] urls, ClassLoader parent) {
            super(urls, parent);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (name.startsWith("sun.misc.")
                || name.startsWith("jdk.internal.")
                || name.endsWith(".kernel.security.CredentialRegistry")
                || name.endsWith(".kernel.security.KernelGuard")
                || name.endsWith(".kernel.security.kmetadata")
                || name.endsWith(".kernel.security.scm")
                || name.endsWith(".kernel.security.smap")) {
                throw new ClassNotFoundException("Kernel Sandbox Blocked Symbol: " + name);
            }
            return super.loadClass(name, resolve);
        }
    }

    public record LoadedModule(
        int pid,
        String name,
        Plugin instance,
        URLClassLoader classLoader,
        scontext ctx
    ) {}

    private final Map<Integer, LoadedModule> modules = new ConcurrentHashMap<>();
    private final Map<Integer, scontext> parentOwners = new ConcurrentHashMap<>();

    public LoadedModule load(scontext parentCtx, File jarPath, String mainClass, int uid, String domain, String name) throws Exception {
        URL[] urls = new URL[]{ jarPath.toURI().toURL() };
        PluginClassLoader pluginClassLoader = new PluginClassLoader(urls, this.getClass().getClassLoader());

        scontext childCtx = parentCtx.syscallSpawn(uid, domain, name);
        int childPid = childCtx.getPid();

        try {
            Class<?> clazz = Class.forName(mainClass, true, pluginClassLoader);
            if (!Plugin.class.isAssignableFrom(clazz)) {
                throw new IllegalArgumentException("Target class does not implement Plugin interface: " + mainClass);
            }
            Plugin plugin = (Plugin) clazz.getDeclaredConstructor().newInstance();
            plugin.onLoad(childCtx);

            LoadedModule loaded = new LoadedModule(childPid, name, plugin, pluginClassLoader, childCtx);
            modules.put(childPid, loaded);
            parentOwners.put(childPid, parentCtx);
            return loaded;
        } catch (Throwable t) {
            try {
                parentCtx.syscallDestroy(childCtx);
            } finally {
                pluginClassLoader.close();
            }
            if (t instanceof Exception ex) {
                throw ex;
            }
            throw new RuntimeException("Plugin initialization aborted by kernel trap", t);
        }
    }

    public void unload(int pid) throws Exception {
        LoadedModule module = modules.remove(pid);
        scontext parentCtx = parentOwners.remove(pid);
        if (module == null) {
            return;
        }
        try {
            module.instance().onUnload();
        } finally {
            try {
                if (parentCtx != null) {
                    parentCtx.syscallDestroy(module.ctx());
                }
            } finally {
                module.classLoader().close();
            }
        }
    }
}