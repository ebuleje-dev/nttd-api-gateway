package com.nttd.banking.gateway.fallback;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;

@RestController
public class FallbackController {

    @GetMapping("/fallback/customers")
    public Mono<Map<String, Object>> customerFallback() {
        return Mono.just(buildResponse("customer-service"));
    }

    @GetMapping("/fallback/accounts")
    public Mono<Map<String, Object>> accountFallback() {
        return Mono.just(buildResponse("account-service"));
    }

    @GetMapping("/fallback/credits")
    public Mono<Map<String, Object>> creditFallback() {
        return Mono.just(buildResponse("credit-service"));
    }

    @GetMapping("/fallback/credit-cards")
    public Mono<Map<String, Object>> creditCardFallback() {
        return Mono.just(buildResponse("credit-card-service"));
    }

    @GetMapping("/fallback/debit-cards")
    public Mono<Map<String, Object>> debitCardFallback() {
        return Mono.just(buildResponse("debit-card-service"));
    }

    @GetMapping("/fallback/transactions")
    public Mono<Map<String, Object>> transactionFallback() {
        return Mono.just(buildResponse("transaction-service"));
    }

    @GetMapping("/fallback/reports")
    public Mono<Map<String, Object>> reportFallback() {
        return Mono.just(buildResponse("report-service"));
    }

    @GetMapping("/fallback/yanki")
    public Mono<Map<String, Object>> yankiFallback() {
        return Mono.just(buildResponse("yanki-service"));
    }

    @GetMapping("/fallback/bootcoin")
    public Mono<Map<String, Object>> bootcoinFallback() {
        return Mono.just(buildResponse("bootcoin-service"));
    }

    @GetMapping("/fallback/auth")
    public Mono<Map<String, Object>> authFallback() {
        return Mono.just(buildResponse("auth-service"));
    }

    private Map<String, Object> buildResponse(String serviceName) {
        return Map.of(
                "timestamp", Instant.now(),
                "service", serviceName,
                "message", "Service temporarily unavailable. Please try again later.",
                "status", HttpStatus.SERVICE_UNAVAILABLE.value()
        );
    }
}
