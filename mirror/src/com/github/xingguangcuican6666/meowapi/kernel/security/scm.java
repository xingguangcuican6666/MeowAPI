package com.github.xingguangcuican6666.meowapi.kernel.security;

import java.lang.StackWalker.Option;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

public enum scm {
    INSTANCE;

    private final Object capabilityToken;
    private final AtomicInteger nextPid = new AtomicInteger(1);
    private final AtomicReference<scontext> rootContextRef;

    scm() {
        KernelGuard.verifyModuleIntegrity();
        this.capabilityToken = CredentialRegistry.claimToken();
        scontext root = new scontext(this.capabilityToken);
        CredentialRegistry.registerRoot(this.capabilityToken, root);
        this.rootContextRef = new AtomicReference<>(root);
    }

    public static scm getInstance() {
        KernelGuard.verifyModuleIntegrity();
        return INSTANCE;
    }

    public scontext handoffRootContext() {
        KernelGuard.verifyModuleIntegrity();
        Class<?> caller = StackWalker.getInstance(Option.RETAIN_CLASS_REFERENCE).getCallerClass();
        if (!"com.github.xingguangcuican6666.meowapi.App".equals(caller.getName())) {
            throw new SecurityException("Trap Fault: Unauthorized handoffRootContext caller: " + caller.getName());
        }
        scontext root = this.rootContextRef.getAndSet(null);
        if (root == null) {
            throw new SecurityException("Kernel Panic: Root context already transferred or consumed");
        }
        return root;
    }

    scontext spawn(scontext parent, int requestedUid, String requestedDomain, String name) {
        KernelGuard.verifyModuleIntegrity();
        Class<?> caller = StackWalker.getInstance(Option.RETAIN_CLASS_REFERENCE).getCallerClass();
        if (caller != scontext.class) {
            throw new SecurityException("Trap Fault: spawn must be invoked via scontext syscall");
        }

        CredentialRegistry.Cred parentCred = CredentialRegistry.get(parent);
        policy.check(parentCred, policy.OP_PROCESS_FORK);

        if (requestedUid == 0 || requestedDomain == null || requestedDomain.contains("kernel")) {
            throw new SecurityException("Kernel Attack Blocked: Attempted privilege escalation to UID 0 or kernel domain!");
        }

        policy.checkTransition(parentCred.domain(), requestedDomain);

        int allocatedPid = this.nextPid.getAndIncrement();
        int finalUid = Math.max(requestedUid, 1000);

        scontext child = new scontext(this.capabilityToken);
        CredentialRegistry.registerChild(this.capabilityToken, parent, child, allocatedPid, finalUid, requestedDomain, name);
        return child;
    }

    void destroyContext(scontext caller, scontext target) {
        KernelGuard.verifyModuleIntegrity();
        Class<?> directCaller = StackWalker.getInstance(Option.RETAIN_CLASS_REFERENCE).getCallerClass();
        if (directCaller != scontext.class) {
            throw new SecurityException("Trap Fault: destroyContext must be invoked via scontext syscall");
        }
        CredentialRegistry.unregisterChild(this.capabilityToken, caller, target);
    }
}