package com.nttd.banking.gateway.security;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

/**
 * Service to verify if a JWT token has been revoked (blacklisted).
 * Checks Redis for tokens that have been invalidated by logout.
 *
 * @author NTT Data Banking Team
 * @since 1.0.0
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private static final String BLACKLIST_PREFIX = "token:blacklist:";

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    /**
     * Checks if a token (by its JTI) is in the blacklist.
     *
     * @param jti JWT Token ID (JTI claim)
     * @return Mono<Boolean> true if token is blacklisted, false otherwise
     */
    public Mono<Boolean> isBlacklisted(String jti) {
        if (jti == null || jti.isBlank()) {
            log.warn("JTI is null or empty, considering as not blacklisted");
            return Mono.just(false);
        }

        String key = BLACKLIST_PREFIX + jti;

        return redisTemplate.hasKey(key)
                .doOnNext(exists -> {
                    if (Boolean.TRUE.equals(exists)) {
                        log.warn("Token with JTI {} is blacklisted (revoked)", jti);
                    } else {
                        log.debug("Token with JTI {} is not blacklisted", jti);
                    }
                })
                .onErrorResume(error -> {
                    log.error("Error checking blacklist for JTI {}: {}", jti, error.getMessage());
                    // On Redis error, allow the request (fail-open) to avoid blocking all requests
                    // Consider changing to fail-close (return true) based on security requirements
                    return Mono.just(false);
                });
    }
}
