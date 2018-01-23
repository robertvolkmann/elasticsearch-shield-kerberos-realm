package com.tngtech.elasticsearch.plugin.kerberosrealm.realm;

import org.elasticsearch.shield.authc.RealmConfig;

public interface RolesProvider {
     void setConfig(RealmConfig config);

     String[] getRoles(String principal);
}
