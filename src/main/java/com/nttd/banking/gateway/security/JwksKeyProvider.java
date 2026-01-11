package com.nttd.banking.gateway.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.nttd.banking.gateway.config.SecurityProperties;
import com.nttd.banking.gateway.exception.AuthenticationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * Provider for fetching and caching JWKS (JSON Web Key Set) public keys.
 * Fetches the public key from auth-service and caches it for a configured duration.
 * Supports both direct URLs (http://localhost:8091/...) and service discovery (lb://auth-service/...).
 *
 * @author NTT Data Banking Team
 * @since 1.0.0
 */
@Slf4j
@Component
public class JwksKeyProvider {

    private final WebClient directWebClient;
    private final WebClient loadBalancedWebClient;
    private final SecurityProperties securityProperties;

    private PublicKey cachedPublicKey;
    private Instant cacheExpiration;

    public JwksKeyProvider(
            WebClient.Builder webClientBuilder,
            @Qualifier("loadBalancedWebClientBuilder") WebClient.Builder loadBalancedWebClientBuilder,
            SecurityProperties securityProperties) {
        this.directWebClient = webClientBuilder.build();
        this.loadBalancedWebClient = loadBalancedWebClientBuilder.build();
        this.securityProperties = securityProperties;
    }

    /**
     * Gets the public key, either from cache or by fetching from JWKS endpoint.
     *
     * @return Mono of PublicKey
     */
    public Mono<PublicKey> getPublicKey() {
        // Check if cache is valid
        if (cachedPublicKey != null && cacheExpiration != null && Instant.now().isBefore(cacheExpiration)) {
            log.debug("Using cached public key");
            return Mono.just(cachedPublicKey);
        }

        log.info("Fetching public key from JWKS endpoint: {}", securityProperties.getJwt().getJwksUri());
        return fetchJwks()
                .map(this::parsePublicKey)
                .doOnSuccess(publicKey -> {
                    cachedPublicKey = publicKey;
                    cacheExpiration = Instant.now().plus(Duration.ofSeconds(securityProperties.getJwt().getCacheDuration()));
                    log.info("Public key cached successfully. Cache expires at: {}", cacheExpiration);
                })
                .doOnError(error -> log.error("Error fetching JWKS: {}", error.getMessage()));
    }

    /**
     * Fetches JWKS from auth-service.
     * Automatically chooses the correct WebClient based on the URI scheme:
     * - Direct URLs (http://, https://) → use directWebClient
     * - Service discovery (lb://) → use loadBalancedWebClient
     *
     * @return Mono of JsonNode containing JWKS response
     */
    private Mono<JsonNode> fetchJwks() {
        String jwksUri = securityProperties.getJwt().getJwksUri();

        // Choose the appropriate WebClient based on URI scheme
        WebClient clientToUse = isDirectUrl(jwksUri) ? directWebClient : loadBalancedWebClient;

        log.debug("Fetching JWKS from: {} using {} WebClient",
                jwksUri,
                isDirectUrl(jwksUri) ? "direct" : "load-balanced");

        return clientToUse.get()
                .uri(jwksUri)
                .retrieve()
                .bodyToMono(JsonNode.class)
                .timeout(Duration.ofSeconds(10))
                .onErrorMap(error -> {
                    log.error("Failed to fetch JWKS from {}: {}", jwksUri, error.getMessage());
                    return new AuthenticationException("Authentication service unavailable", error);
                });
    }

    /**
     * Checks if the URI is a direct URL (http:// or https://).
     *
     * @param uri the URI to check
     * @return true if direct URL, false if service discovery (lb://)
     */
    private boolean isDirectUrl(String uri) {
        return uri != null && (uri.startsWith("http://") || uri.startsWith("https://"));
    }

    /**
     * Parses JWKS JSON response to extract RSA public key.
     *
     * @param jwks JWKS JSON response
     * @return PublicKey
     */
    private PublicKey parsePublicKey(JsonNode jwks) {
        try {
            JsonNode keys = jwks.get("keys");
            if (keys == null || !keys.isArray() || keys.isEmpty()) {
                throw new AuthenticationException("Invalid JWKS format: no keys found");
            }

            // Get the first key (assuming single key for now)
            JsonNode key = keys.get(0);

            String kty = key.get("kty").asText();
            if (!"RSA".equals(kty)) {
                throw new AuthenticationException("Unsupported key type: " + kty);
            }

            // Extract modulus (n) and exponent (e) from JWKS
            String modulusBase64 = key.get("n").asText();
            String exponentBase64 = key.get("e").asText();

            // Decode base64url to BigInteger
            BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(modulusBase64));
            BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(exponentBase64));

            // Create RSA public key
            RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(spec);

            log.debug("Public key parsed successfully");
            return publicKey;

        } catch (Exception e) {
            throw new AuthenticationException("Failed to parse JWKS public key", e);
        }
    }

    /**
     * Clears the cached public key (for testing or manual refresh).
     */
    public void clearCache() {
        cachedPublicKey = null;
        cacheExpiration = null;
        log.info("Public key cache cleared");
    }
}
