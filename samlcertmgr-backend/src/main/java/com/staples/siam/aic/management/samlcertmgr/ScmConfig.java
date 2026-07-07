package com.staples.siam.aic.management.samlcertmgr;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.dropwizard.core.Configuration;
import lombok.Getter;

public class ScmConfig extends Configuration {
    @Getter
    public static class Tenant {
        String tenantUrl;
        String svcacctId;
        String svcacctKeyPath;
    }
    
    @JsonProperty
    public Tenant tenant;
}
