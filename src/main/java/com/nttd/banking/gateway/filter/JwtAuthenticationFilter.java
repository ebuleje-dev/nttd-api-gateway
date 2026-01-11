package com.nttd.banking.gateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nttd.banking.gateway.config.SecurityProperties;
import com.nttd.banking.gateway.exception.AuthenticationException;
import com.nttd.banking.gateway.security.JwtValidator;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;

/**
 * Global JWT authentication filter for Spring Cloud Gateway.
 * Validates JWT tokens and propagates user information to downstream services.
 *
 * @author NTT Data Banking Team
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtValidator jwtValidator;
    private final SecurityProperties securityProperties;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getPath().toString();

        // Check if path is public
        if (isPublicPath(path)) {
            log.debug("Public path accessed: {}", path);
            return chain.filter(exchange);
        }

        // Extract token from Authorization header
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Missing authorization token for path: {}", path);
            return onError(exchange, "Missing authorization token", HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7); // Remove "Bearer " prefix

        // Validate token and propagate user info
        return jwtValidator.validateToken(token)
                .flatMap(claims -> {
                    // Add user info headers for downstream services
                    ServerWebExchange mutatedExchange = addUserHeaders(exchange, claims);
                    return chain.filter(mutatedExchange);
                })
                .onErrorResume(AuthenticationException.class, error -> {
                    log.warn("Authentication failed for path {}: {}", path, error.getMessage());
                    HttpStatus status = error.getMessage().contains("unavailable")
                            ? HttpStatus.SERVICE_UNAVAILABLE
                            : HttpStatus.UNAUTHORIZED;
                    return onError(exchange, error.getMessage(), status);
                });
    }

    /**
     * Checks if the request path is public (doesn't require authentication).
     *
     * @param path request path
     * @return true if public, false otherwise
     */
    private boolean isPublicPath(String path) {
        return securityProperties.getPublicPaths().stream()
                .anyMatch(pattern -> pathMatcher.match(pattern, path));
    }

    /**
     * Adds user information headers to the request for downstream services.
     *
     * @param exchange ServerWebExchange
     * @param claims JWT claims
     * @return mutated ServerWebExchange with added headers
     */
    private ServerWebExchange addUserHeaders(ServerWebExchange exchange, Claims claims) {
        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .header("X-User-Id", jwtValidator.getUserId(claims))
                .header("X-Username", jwtValidator.getUsername(claims))
                .header("X-User-Roles", jwtValidator.getRoles(claims))
                .header("X-User-Type", jwtValidator.getUserType(claims))
                .build();

        log.debug("User headers added: userId={}, username={}, roles={}",
                jwtValidator.getUserId(claims),
                jwtValidator.getUsername(claims),
                jwtValidator.getRoles(claims));

        return exchange.mutate().request(mutatedRequest).build();
    }

    /**
     * Returns an error response with JSON body.
     *
     * @param exchange ServerWebExchange
     * @param message error message
     * @param status HTTP status
     * @return Mono<Void>
     */
    private Mono<Void> onError(ServerWebExchange exchange, String message, HttpStatus status) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> errorBody = Map.of(
                "timestamp", Instant.now().toString(),
                "status", status.value(),
                "error", status.getReasonPhrase(),
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
        return -100; // Run before most filters but after logging
    }
}
