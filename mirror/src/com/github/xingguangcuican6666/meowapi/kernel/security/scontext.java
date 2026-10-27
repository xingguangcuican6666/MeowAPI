package com.github.xingguangcuican6666.meowapi.kernel.security;

import java.lang.StackWalker.Option;

public final class scontext {

    scontext() {
        throw new SecurityException("Unauthorized scontext construction");
    }

    scontext(int pid, int uid, String domain) {
        throw new SecurityException("Direct construction disabled");
    }

    scontext(Object token) {
        KernelGuard.verifyModuleIntegrity();
        Class<?> caller = StackWalker.getInstance(Option.RETAIN_CLASS_REFERENCE).getCallerClass();
        if (caller != scm.class || !CredentialRegistry.verifyToken(token)) {
            throw new SecurityException("Trap Fault: Forged scontext construction attempt blocked");
        }
    }

    public int getPid() {
        CredentialRegistry.Cred cred = CredentialRegistry.get(this);
        return cred != null ? cred.pid() : -1;
    }

    public int getUid() {
        CredentialRegistry.Cred cred = CredentialRegistry.get(this);
        return cred != null ? cred.uid() : -1;
    }

    public String getDomain() {
        CredentialRegistry.Cred cred = CredentialRegistry.get(this);
        return cred != null ? cred.domain() : "u:r:untrusted:s0";
    }

    public void syscallSetMetadata(String key, Object value) {
        kmetadata.write(this, key, value);
    }

    public Object syscallGetMetadata(String key) {
        return kmetadata.read(this, key);
    }

    public scontext syscallSpawn(int uid, String domain, String name) {
        return scm.INSTANCE.spawn(this, uid, domain, name);
    }

    public void syscallDestroy(scontext target) {
        scm.INSTANCE.destroyContext(this, target);
    }
}