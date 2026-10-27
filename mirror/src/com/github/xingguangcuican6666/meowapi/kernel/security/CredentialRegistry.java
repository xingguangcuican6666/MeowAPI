package com.github.xingguangcuican6666.meowapi.kernel.security;

import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

record CredentialRegistry() {

    record Cred(int pid, int uid, int ppid, String domain, String name, String hash) {}

    private record Vault(
        Map<scontext, Cred> byCtx,
        Map<Integer, scontext> byPid,
        Map<Integer, Map<String, Object>> propsByPid,
        AtomicBoolean rootSealed,
        Object token
    ) {}

    private static final Vault VAULT = new Vault(
        Collections.synchronizedMap(new IdentityHashMap<>()),
        new ConcurrentHashMap<>(),
        new ConcurrentHashMap<>(),
        new AtomicBoolean(false),
        new Object()
    );

    private static final AtomicBoolean TOKEN_CLAIMED = new AtomicBoolean(false);

    static Object claimToken() {
        KernelGuard.verifyModuleIntegrity();
        if (!TOKEN_CLAIMED.compareAndSet(false, true)) {
            throw new SecurityException("Kernel Panic: Capability token already claimed");
        }
        return VAULT.token();
    }

    static boolean verifyToken(Object candidate) {
        return candidate != null && candidate == VAULT.token();
    }

    static void register(scontext ctx, Object cred) {
        throw new SecurityException("Direct register disabled");
    }

    static void unregister(scontext ctx) {
        throw new SecurityException("Direct unregister disabled");
    }

    static void registerRoot(Object token, scontext root) {
        KernelGuard.requireDirectScmCaller(token, VAULT.token());
        if (root == null) {
            throw new SecurityException("Null root context");
        }
        if (!VAULT.rootSealed().compareAndSet(false, true)) {
            throw new SecurityException("Kernel Panic: PID 0 root context already sealed");
        }

        synchronized (VAULT.byCtx()) {
            if (!VAULT.byCtx().isEmpty() || !VAULT.byPid().isEmpty()) {
                throw new SecurityException("Kernel Panic: Registry not empty during root genesis");
            }
            String hash = Integer.toHexString(System.identityHashCode(root));
            Cred rootCred = new Cred(0, 0, 0, "u:r:kernel:s0", "init", hash);
            VAULT.byCtx().put(root, rootCred);
            VAULT.byPid().put(0, root);
            VAULT.propsByPid().put(0, Map.of(
                "pid", 0,
                "uid", 0,
                "context", "u:r:kernel:s0",
                "name", "init",
                "hash", hash
            ));
        }
    }

    static void registerChild(
        Object token,
        scontext parent,
        scontext child,
        int pid,
        int uid,
        String domain,
        String name
    ) {
        KernelGuard.requireDirectScmCaller(token, VAULT.token());
        if (!VAULT.rootSealed().get()) {
            throw new SecurityException("Kernel Panic: Root not initialized");
        }
        if (parent == null || child == null || parent == child) {
            throw new SecurityException("Invalid context reference");
        }

        Cred parentCred = get(parent);
        policy.check(parentCred, policy.OP_PROCESS_FORK);

        if (pid <= 0 || uid < 1000 || domain == null || domain.contains("kernel")) {
            throw new SecurityException("Kernel Attack Blocked: Illegal child PID/UID/Domain");
        }

        policy.checkTransition(parentCred.domain(), domain);

        synchronized (VAULT.byCtx()) {
            if (VAULT.byCtx().containsKey(child) || VAULT.byPid().containsKey(pid)) {
                throw new SecurityException("Kernel Attack Blocked: Duplicate context or PID " + pid);
            }
            String hash = Integer.toHexString(System.identityHashCode(child));
            Cred childCred = new Cred(pid, uid, parentCred.pid(), domain, name, hash);
            VAULT.byCtx().put(child, childCred);
            VAULT.byPid().put(pid, child);
            VAULT.propsByPid().put(pid, Map.of(
                "pid", pid,
                "uid", uid,
                "ppid", parentCred.pid(),
                "context", domain,
                "name", name,
                "hash", hash
            ));
        }
    }

    static void unregisterChild(Object token, scontext caller, scontext target) {
        KernelGuard.requireDirectScmCaller(token, VAULT.token());
        Cred callerCred = get(caller);
        policy.check(callerCred, policy.OP_PROCESS_FORK);

        Cred targetCred = get(target);
        if (targetCred == null) {
            return;
        }
        if (targetCred.pid() == 0 || "u:r:kernel:s0".equals(targetCred.domain())) {
            throw new SecurityException("Kernel Attack Blocked: Cannot unregister PID 0 or kernel domain");
        }

        synchronized (VAULT.byCtx()) {
            VAULT.byCtx().remove(target);
            VAULT.byPid().remove(targetCred.pid(), target);
            VAULT.propsByPid().remove(targetCred.pid());
        }
    }

    static Cred get(scontext ctx) {
        KernelGuard.verifyModuleIntegrity();
        if (ctx == null) {
            return null;
        }
        synchronized (VAULT.byCtx()) {
            Cred cred = VAULT.byCtx().get(ctx);
            if (cred == null) {
                return null;
            }
            if (VAULT.byPid().get(cred.pid()) != ctx) {
                throw new SecurityException("Kernel Panic: Credential PID mapping mismatch");
            }
            String expectedHash = Integer.toHexString(System.identityHashCode(ctx));
            if (!expectedHash.equals(cred.hash())) {
                throw new SecurityException("Kernel Panic: Context identity hash mismatch");
            }
            return cred;
        }
    }

    static List<Map<Integer, Map<String, Object>>> snapshotSmap() {
        KernelGuard.verifyModuleIntegrity();
        List<Integer> pids = new ArrayList<>(VAULT.propsByPid().keySet());
        Collections.sort(pids);
        List<Map<Integer, Map<String, Object>>> result = new ArrayList<>(pids.size());
        for (Integer pid : pids) {
            Map<String, Object> props = VAULT.propsByPid().get(pid);
            if (props != null) {
                result.add(Map.of(pid, props));
            }
        }
        return Collections.unmodifiableList(result);
    }
}