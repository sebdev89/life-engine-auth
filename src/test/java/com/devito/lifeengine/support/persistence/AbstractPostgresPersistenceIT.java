package com.devito.lifeengine.support.persistence;

import com.devito.lifeengine.LifeEngineAuthApplication;
import com.devito.lifeengine.support.integration.LifeEngineModulithPostgresItSupport;
import org.junit.jupiter.api.Tag;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Shared Postgres + Flyway + full application persistence context (no HTTP). Uses the same Testcontainers singleton as
 * {@link com.devito.lifeengine.support.integration.AbstractModulithWebFluxIntegrationIT} so repository IT classes can
 * coexist in one Failsafe fork without restarting the database between classes.
 *
 * <p>Layout (under {@code apps/core-app/src/test/java}):
 *
 * <pre>
 * com.devito.lifeengine.support.persistence/
 *   AbstractPostgresPersistenceIT.java
 * com.devito.lifeengine.auth.persistence/
 *   AuthSessionRefreshTokenPersistenceIT.java
 * com.devito.lifeengine.devagent.persistence/
 *   DevAgentTaskRunPersistenceIT.java
 * com.devito.lifeengine.memoryrag.persistence/
 *   MemoryRagDocumentChunkPersistenceIT.java
 * </pre>
 */
@Tag("integration")
@Tag("persistence")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, classes = LifeEngineAuthApplication.class)
@ActiveProfiles("test")
public abstract class AbstractPostgresPersistenceIT {

    protected static final String IT_JWT_SECRET =
            "0123456789012345678901234567890123456789012345678901234567890123";
    protected static final String BOOTSTRAP_EMAIL = "it-admin@life-engine.local";
    protected static final String BOOTSTRAP_PASSWORD = "ItBootstrap_Admin_Pass1!";

    @DynamicPropertySource
    static void registerPersistenceDatasource(DynamicPropertyRegistry r) {
        LifeEngineModulithPostgresItSupport.registerDatasource(r, IT_JWT_SECRET, BOOTSTRAP_EMAIL, BOOTSTRAP_PASSWORD);
    }
}
