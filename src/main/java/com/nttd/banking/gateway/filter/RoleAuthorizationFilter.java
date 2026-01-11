package com.nttd.banking.gateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nttd.banking.gateway.config.AuthorizationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Role-based authorization filter for Spring Cloud Gateway.
 * Validates that the authenticated user has the required roles to access the requested resource.
 * This filter runs AFTER JwtAuthenticationFilter (which sets X-User-Roles header).
 *
 * @author NTT Data Banking Team
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RoleAuthorizationFilter implements GlobalFilter, Ordered {

    private final AuthorizationProperties authorizationProperties;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // Skip if authorization is disabled
        if (!authorizationProperties.isEnabled()) {
            return chain.filter(exchange);
        }

        String path = exchange.getRequest().getPath().toString();
        String userRolesHeader = exchange.getRequest().getHeaders().getFirst("X-User-Roles");

        // If no roles header, authentication didn't happen (public route), skip authorization
        if (userRolesHeader == null || userRolesHeader.isEmpty()) {
            log.debug("No user roles found for path: {} (likely a public route)", path);
            return chain.filter(exchange);
        }

        // Parse user roles from comma-separated header
        List<String> userRoles = Arrays.asList(userRolesHeader.split(","));
        log.debug("User roles: {} for path: {}", userRoles, path);

        // Check if user has super admin role (access to everything)
        if (hasSuperAdminRole(userRoles)) {
            log.debug("Super admin access granted for path: {}", path);
            return chain.filter(exchange);
        }

        // Check if user has required role for this route
        if (hasRequiredRole(path, userRoles)) {
            log.debug("Access granted for path: {} with roles: {}", path, userRoles);
            return chain.filter(exchange);
        }

        // Access denied
        log.warn("Access denied for path: {} with roles: {}", path, userRoles);
        return onAccessDenied(exchange, "Insufficient permissions to access this resource");
    }

    /**
     * Checks if user has a super admin role (full access).
     *
     * @param userRoles list of user's roles
     * @return true if user is super admin
     */
    private boolean hasSuperAdminRole(List<String> userRoles) {
        return userRoles.stream()
                .anyMatch(role -> authorizationProperties.getSuperAdminRoles().contains(role.trim()));
    }

    /**
     * Checks if user has the required role to access the path.
     *
     * @param path request path
     * @param userRoles list of user's roles
     * @return true if user has required role
     */
    private boolean hasRequiredRole(String path, List<String> userRoles) {
        // Find matching route pattern
        for (Map.Entry<String, List<String>> entry : authorizationProperties.getRouteRoles().entrySet()) {
            String routePattern = entry.getKey();
            List<String> allowedRoles = entry.getValue();

            // Check if path matches the route pattern
            if (pathMatcher.match(routePattern, path)) {
                log.debug("Route pattern {} matches path {}", routePattern, path);

                // Check if user has any of the allowed roles
                boolean hasRole = userRoles.stream()
                        .anyMatch(userRole -> allowedRoles.contains(userRole.trim()));

                if (hasRole) {
                    return true;
                } else {
                    log.debug("User roles {} do not match allowed roles {} for pattern {}",
                            userRoles, allowedRoles, routePattern);
                    return false;
                }
            }
        }

        // If no route pattern matches, allow access by default
        // (This is safe because authentication already happened)
        log.debug("No specific authorization rule for path: {}, allowing access", path);
        return true;
    }

    /**
     * Returns a 403 Forbidden response.
     *
     * @param exchange ServerWebExchange
     * @param message error message
     * @return Mono<Void>
     */
    private Mono<Void> onAccessDenied(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.FORBIDDEN);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> errorBody = Map.of(
                "timestamp", Instant.now().toString(),
                "status", HttpStatus.FORBIDDEN.value(),
                "error", HttpStatus.FORBIDDEN.getReasonPhrase(),
                "message", message,
                "path", exchange.getRequest().getPath().toString()
        );

        try {
            byte[] bytes = objectMapper.writeValueAsString(errorBody).getBytes(StandardCharsets.UTF_8);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        } catch (JsonProcessingException e) {
            log.error("Error creating error response", e);
            return response.setComplete();
        }
    }

    @Override
    public int getOrder() {
        // Run AFTER JwtAuthenticationFilter (which is -100)
        return -50;
    }
}
