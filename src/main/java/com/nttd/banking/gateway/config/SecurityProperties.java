package com.nttd.banking.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Security configuration properties.
 * Maps to 'security' prefix in application.yaml.
 *
 * @author NTT Data Banking Team
 * @since 1.0.0
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    private Jwt jwt = new Jwt();
    private List<String> publicPaths = List.of();

    /**
     * JWT configuration properties.
     */
    @Data
    public static class Jwt {
        /**
         * JWKS URI (e.g., lb://auth-service/api/auth/.well-known/jwks.json).
         */
        private String jwksUri;

        /**
         * Cache duration in seconds (default: 300 = 5 minutes).
         */
        private long cacheDuration = 300;
    }
}
