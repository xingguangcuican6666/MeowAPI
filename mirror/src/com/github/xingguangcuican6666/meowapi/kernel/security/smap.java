package com.github.xingguangcuican6666.meowapi.kernel.security;

import java.util.AbstractList;
import java.util.List;
import java.util.Map;

public final class smap {

    public static final List<Map<Integer, Map<String, Object>>> smetadata = new AbstractList<>() {
        @Override
        public Map<Integer, Map<String, Object>> get(int index) {
            return CredentialRegistry.snapshotSmap().get(index);
        }

        @Override
        public int size() {
            return CredentialRegistry.snapshotSmap().size();
        }
    };

    private smap() {
        throw new SecurityException("Instantiation disabled");
    }
}