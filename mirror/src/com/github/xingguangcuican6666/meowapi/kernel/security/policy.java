package com.github.xingguangcuican6666.meowapi.kernel.security;

import java.util.Map;
import java.util.Set;

public final class policy {

    public static final String OP_METADATA_WRITE = "metadata:write";
    public static final String OP_METADATA_READ = "metadata:read";
    public static final String OP_PROCESS_FORK = "process:fork";
    public static final String OP_ROUTE_REGISTER = "route:register";

    private static final Map<String, Set<String>> TRANSITIONS = Map.of(
        "u:r:kernel:s0", Set.of("u:r:plugin:s0", "u:r:untrusted:s0"),
        "u:r:plugin:s0", Set.of()
    );

    private policy() {
        throw new SecurityException("Instantiation disabled");
    }

    static void check(CredentialRegistry.Cred cred, String operation) {
        KernelGuard.verifyModuleIntegrity();
        if (cred == null) {
            throw new SecurityException("avc: denied { " + operation + " } for unauthenticated context");
        }

        boolean allowed = switch (cred.domain()) {
            case "u:r:kernel:s0" -> cred.pid() == 0 && cred.uid() == 0;
            case "u:r:plugin:s0" -> cred.pid() > 0 && cred.uid() >= 1000 && OP_METADATA_READ.equals(operation);
            default -> false;
        };

        if (!allowed) {
            throw new SecurityException("avc: denied { " + operation + " } for domain=" + cred.domain() + " pid=" + cred.pid());
        }
    }

    static void checkTransition(String fromDomain, String toDomain) {
        KernelGuard.verifyModuleIntegrity();
        Set<String> targets = TRANSITIONS.get(fromDomain);
        if (targets == null || !targets.contains(toDomain)) {
            throw new SecurityException("avc: denied { transition } from=" + fromDomain + " to=" + toDomain);
        }
    }
}