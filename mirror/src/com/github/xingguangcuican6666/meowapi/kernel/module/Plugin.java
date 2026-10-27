package com.github.xingguangcuican6666.meowapi.kernel.module;

import com.github.xingguangcuican6666.meowapi.kernel.security.scontext;

public interface Plugin {
    void onLoad(scontext ctx) throws Exception;
    void onUnload() throws Exception;
}