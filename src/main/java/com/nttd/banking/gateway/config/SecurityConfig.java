package com.nttd.banking.gateway.config;

import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Security configuration for API Gateway.
 * Configures beans needed for JWT authentication.
 * Provides two WebClient beans: one for direct URLs and one for service discovery.
 *
 * @author NTT Data Banking Team
 * @since 1.0.0
 */
@Configuration
public class SecurityConfig {

    /**
     * Creates a standard WebClient bean for direct HTTP/HTTPS URLs.
     * Used when the JWKS URI is a direct URL like http://localhost:8091/...
     * This is the primary bean and will be injected by default.
     *
     * @return WebClient.Builder for direct URLs
     */
    @Bean
    @Primary
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }

    /**
     * Creates a LoadBalanced WebClient bean for service discovery URLs (lb://).
     * Used when the JWKS URI uses Eureka service discovery like lb://auth-service/...
     * The @LoadBalanced annotation enables resolution of lb:// URIs through Eureka.
     *
     * @return WebClient.Builder with load balancing support
     */
    @Bean
    @LoadBalanced
    public WebClient.Builder loadBalancedWebClientBuilder() {
        return WebClient.builder();
    }
}
