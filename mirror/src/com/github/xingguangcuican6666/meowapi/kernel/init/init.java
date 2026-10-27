package com.github.xingguangcuican6666.meowapi.kernel.init;

import com.github.xingguangcuican6666.meowapi.kernel.module.moduleloader;
import com.github.xingguangcuican6666.meowapi.kernel.security.scontext;
import java.io.File;

public class init {

    private final scontext ctx;
    private final moduleloader loader;

    public init(scontext ctx) {
        this.ctx = ctx;
        this.loader = new moduleloader();
    }

    public void start() {
        try {
            File pluginJar = new File("plugins/plugin-openai.jar");
            if (pluginJar.exists()) {
                this.loader.load(
                    this.ctx,
                    pluginJar,
                    "com.github.xingguangcuican6666.meowapi.plugin.openai.OpenAIPlugin",
                    1001,
                    "u:r:plugin:s0",
                    "openai-adapter"
                );
            }
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
}