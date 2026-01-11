package com.nttd.banking.gateway.security;

import com.nttd.banking.gateway.exception.AuthenticationException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.security.PublicKey;
import java.util.List;

/**
 * JWT token validator using JWKS public key.
 *
 * @author NTT Data Banking Team
 * @since 1.0.0
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtValidator {

    private final JwksKeyProvider jwksKeyProvider;

    /**
     * Validates a JWT token and extracts claims.
     *
     * @param token JWT token string (without "Bearer " prefix)
     * @return Mono of Claims if valid
     * @throws AuthenticationException if token is invalid or expired
     */
    public Mono<Claims> validateToken(String token) {
        return jwksKeyProvider.getPublicKey()
                .flatMap(publicKey -> parseToken(token, publicKey))
                .doOnError(error -> log.error("Token validation failed: {}", error.getMessage()));
    }

    /**
     * Parses and validates the JWT token using the public key.
     *
     * @param token JWT token string
     * @param publicKey RSA public key
     * @return Mono of Claims
     */
    private Mono<Claims> parseToken(String token, PublicKey publicKey) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            log.debug("Token validated successfully for user: {}", claims.getSubject());
            return Mono.just(claims);

        } catch (ExpiredJwtException e) {
            log.warn("Token expired for user: {}", e.getClaims().getSubject());
            return Mono.error(new AuthenticationException("Token expired"));

        } catch (SignatureException e) {
            log.warn("Invalid token signature");
            return Mono.error(new AuthenticationException("Invalid token"));

        } catch (MalformedJwtException e) {
            log.warn("Malformed JWT token");
            return Mono.error(new AuthenticationException("Invalid token"));

        } catch (Exception e) {
            log.error("Token validation error: {}", e.getMessage());
            return Mono.error(new AuthenticationException("Invalid token", e));
        }
    }

    /**
     * Extracts user ID from claims (sub).
     *
     * @param claims JWT claims
     * @return user ID
     */
    public String getUserId(Claims claims) {
        return claims.getSubject();
    }

    /**
     * Extracts username from claims.
     *
     * @param claims JWT claims
     * @return username
     */
    public String getUsername(Claims claims) {
        return claims.get("username", String.class);
    }

    /**
     * Extracts user type from claims.
     *
     * @param claims JWT claims
     * @return user type
     */
    public String getUserType(Claims claims) {
        return claims.get("userType", String.class);
    }

    /**
     * Extracts roles from claims and converts to comma-separated string.
     *
     * @param claims JWT claims
     * @return comma-separated roles
     */
    @SuppressWarnings("unchecked")
    public String getRoles(Claims claims) {
        List<String> roles = claims.get("roles", List.class);
        if (roles == null || roles.isEmpty()) {
            return "";
        }
        return String.join(",", roles);
    }
}
