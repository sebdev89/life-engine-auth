package com.devito.lifeengine.auth;

import org.springframework.modulith.ApplicationModule;

@ApplicationModule(
        displayName = "Auth",
        type = ApplicationModule.Type.OPEN,
        allowedDependencies = {"shared :: events", "platform"})
public class AuthModule {}