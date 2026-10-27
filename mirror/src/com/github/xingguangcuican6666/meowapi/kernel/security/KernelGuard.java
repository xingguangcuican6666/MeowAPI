package com.github.xingguangcuican6666.meowapi.kernel.security;

import java.lang.StackWalker.Option;
import java.lang.StackWalker.StackFrame;
import java.util.List;

record KernelGuard() {

    private static final StackWalker WALKER = StackWalker.getInstance(Option.RETAIN_CLASS_REFERENCE);
    private static final String SEC_PKG = KernelGuard.class.getPackageName();

    static void verifyModuleIntegrity() {
        Module module = KernelGuard.class.getModule();
        if (!module.isNamed() || !"meowapi.kernel".equals(module.getName())) {
            throw new SecurityException("Kernel Panic: Unnamed module (-cp) boot forbidden; must launch via JPMS module path (-p)");
        }
        Module unnamed = ClassLoader.getSystemClassLoader().getUnnamedModule();
        if (module.isOpen(SEC_PKG) || module.isOpen(SEC_PKG, unnamed)) {
            throw new SecurityException("Kernel Panic: Illegal reflective open detected on " + SEC_PKG);
        }
    }

    static void requireDirectScmCaller(Object providedToken, Object expectedToken) {
        verifyModuleIntegrity();
        if (providedToken == null || providedToken != expectedToken) {
            throw new SecurityException("Trap Fault: Invalid kernel capability token");
        }

        List<StackFrame> frames = WALKER.walk(s -> s.limit(8).toList());
        if (frames.size() < 3) {
            throw new SecurityException("Trap Fault: Corrupted call stack");
        }

        Class<?> directCaller = frames.get(2).getDeclaringClass();
        if (directCaller != scm.class) {
            throw new SecurityException("Trap Fault: Direct caller must be scm, got " + directCaller.getName());
        }

        for (StackFrame frame : frames) {
            String cn = frame.getDeclaringClass().getName();
            if (cn.startsWith("java.lang.reflect.")
                || cn.startsWith("jdk.internal.reflect.")
                || cn.startsWith("java.lang.invoke.")
                || cn.startsWith("sun.misc.")) {
                throw new SecurityException("Trap Fault: Reflective or synthetic invocation blocked: " + cn);
            }
        }
    }
}