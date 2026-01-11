package com.nttd.banking.gateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Authorization configuration properties for role-based access control.
 * Maps routes to allowed roles.
 *
 * @author NTT Data Banking Team
 * @since 1.0.0
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "authorization")
public class AuthorizationProperties {

    /**
     * Map of route patterns to allowed roles.
     * Key: Route pattern (supports Ant-style patterns like /api/v1/customers/**)
     * Value: List of roles that can access this route
     *
     * Example:
     * route-roles:
     *   /api/v1/customers/**:
     *     - ROLE_ADMIN
     *     - ROLE_CUSTOMER
     */
    private Map<String, List<String>> routeRoles = new HashMap<>();

    /**
     * Roles that have access to all endpoints (super admin).
     * Default: ROLE_ADMIN
     */
    private List<String> superAdminRoles = new ArrayList<>(List.of("ROLE_ADMIN"));

    /**
     * Enable or disable role-based authorization.
     * If false, only authentication is performed (no authorization).
     * Default: true
     */
    private boolean enabled = true;
}
