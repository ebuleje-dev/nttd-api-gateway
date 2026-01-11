package com.nttd.banking.gateway.config;

import org.springframework.context.annotation.Configuration;

/**
 * Gateway configuration.
 * Routes are configured in application.yml from Config Server.
 * Global filters (JwtAuthenticationFilter, RoleAuthorizationFilter) are automatically
 * applied as they implement GlobalFilter interface.
 *
 * @author NTT Data Banking Team
 * @since 1.0.0
 */
@Configuration
public class GatewayConfig {
    // Global filters are auto-registered via @Component and GlobalFilter interface
    // No manual configuration needed
}
