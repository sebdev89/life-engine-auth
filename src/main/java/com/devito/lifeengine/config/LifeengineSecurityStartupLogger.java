package com.devito.lifeengine.config;

import com.devito.lifeengine.auth.infrastructure.config.GuestAuthProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

@Component
@Order
public class LifeengineSecurityStartupLogger {

    private static final Logger LOG = LoggerFactory.getLogger(LifeengineSecurityStartupLogger.class);

    private final Environment environment;
    private final GuestAuthProperties guestAuthProperties;

    public LifeengineSecurityStartupLogger(Environment environment, GuestAuthProperties guestAuthProperties) {
        this.environment = environment;
        this.guestAuthProperties = guestAuthProperties;
    }

    @EventListener(ContextRefreshedEvent.class)
    public void onReady(ContextRefreshedEvent event) {
        if (event.getApplicationContext().getParent() != null) {
            return;
        }
        String appEnv = environment.getProperty("lifeengine.deployment.env", "").trim().toLowerCase();
        String profiles = String.join(",", environment.getActiveProfiles());
        boolean guestOn = guestAuthProperties.isEnabled();
        boolean prodLike = "prod".equals(appEnv);

        boolean riskyProd =
                prodLike
                        && (flag("lifeengine.security.admin-seed.enabled")
                                || flag("lifeengine.security.local-dev-operator-seed.enabled")
                                || flag("lifeengine.security.local-dev-password-rotation-seed.enabled")
                                || flag("lifeengine.security.dev-password-reset.enabled")
                                || flag("lifeengine.security.password-reset.expose-token-for-testing"));

        String msg =
                "lifeengine_security_bootstrap appEnv={} springProfiles={} guestAuthEnabled={} defaultHttpSecurity=denyUnmatched";

        if (guestOn) {
            LOG.warn(msg + " note=guest_auth_enabled", appEnv, profiles, guestOn);
        } else if (riskyProd) {
            LOG.warn(msg + " note=prod_with_dev_or_test_security_flags", appEnv, profiles, guestOn);
        } else {
            LOG.info(msg, appEnv, profiles, guestOn);
        }
    }

    private boolean flag(String key) {
        return Boolean.parseBoolean(environment.getProperty(key, "false"));
    }
}
