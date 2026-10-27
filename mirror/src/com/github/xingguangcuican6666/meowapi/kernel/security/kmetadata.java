package com.github.xingguangcuican6666.meowapi.kernel.security;

import java.lang.StackWalker.Option;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

record kmetadata() {

    private record StorageHolder(Map<String, Object> map) {}

    private static final StorageHolder HOLDER = new StorageHolder(new ConcurrentHashMap<>());
    private static final StackWalker WALKER = StackWalker.getInstance(Option.RETAIN_CLASS_REFERENCE);

    static void write(scontext ctx, String key, Object value) {
        KernelGuard.verifyModuleIntegrity();
        Class<?> caller = WALKER.getCallerClass();
        if (caller != scontext.class) {
            throw new SecurityException("Trap Fault: Direct call from non-scontext caller [" + caller.getName() + "]");
        }

        CredentialRegistry.Cred cred = CredentialRegistry.get(ctx);
        policy.check(cred, policy.OP_METADATA_WRITE);
        HOLDER.map().put(key, value);
    }

    static Object read(scontext ctx, String key) {
        KernelGuard.verifyModuleIntegrity();
        Class<?> caller = WALKER.getCallerClass();
        if (caller != scontext.class) {
            throw new SecurityException("Trap Fault: Direct call from non-scontext caller [" + caller.getName() + "]");
        }

        CredentialRegistry.Cred cred = CredentialRegistry.get(ctx);
        policy.check(cred, policy.OP_METADATA_READ);
        return HOLDER.map().get(key);
    }

    static Map<String, Object> snapshot(scontext ctx) {
        KernelGuard.verifyModuleIntegrity();
        CredentialRegistry.Cred cred = CredentialRegistry.get(ctx);
        policy.check(cred, policy.OP_METADATA_READ);
        return Collections.unmodifiableMap(HOLDER.map());
    }
}