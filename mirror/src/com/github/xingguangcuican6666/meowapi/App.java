package com.github.xingguangcuican6666.meowapi;

import com.github.xingguangcuican6666.meowapi.kernel.init.init;
import com.github.xingguangcuican6666.meowapi.kernel.security.scm;
import com.github.xingguangcuican6666.meowapi.kernel.security.scontext;
import java.util.concurrent.atomic.AtomicBoolean;

public class App {

    private static final AtomicBoolean BOOTED = new AtomicBoolean(false);

    public static void main(String[] args) {
        if (!BOOTED.compareAndSet(false, true)) {
            throw new SecurityException("Panic: Re-entrant boot attempt detected");
        }

        scontext rootContext = scm.getInstance().handoffRootContext();
        init initProcess = new init(rootContext);
        initProcess.start();
    }
}