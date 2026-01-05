package com.nttd.banking.gateway.fallback;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.Map;

@RestController
public class FallbackController {

    @RequestMapping("/fallback/customers")
    public Mono<Map<String, Object>> customerFallback() {
        return Mono.just(buildResponse("customer-service"));
    }

    @RequestMapping("/fallback/accounts")
    public Mono<Map<String, Object>> accountFallback() {
        return Mono.just(buildResponse("account-service"));
    }

    @RequestMapping("/fallback/credits")
    public Mono<Map<String, Object>> creditFallback() {
        return Mono.just(buildResponse("credit-service"));
    }

    @RequestMapping("/fallback/credit-cards")
    public Mono<Map<String, Object>> creditCardFallback() {
        return Mono.just(buildResponse("credit-card-service"));
    }

    @RequestMapping("/fallback/debit-cards")
    public Mono<Map<String, Object>> debitCardFallback() {
        return Mono.just(buildResponse("debit-card-service"));
    }

    @RequestMapping("/fallback/transactions")
    public Mono<Map<String, Object>> transactionFallback() {
        return Mono.just(buildResponse("transaction-service"));
    }

    @RequestMapping("/fallback/reports")
    public Mono<Map<String, Object>> reportFallback() {
        return Mono.just(buildResponse("report-service"));
    }

    @RequestMapping("/fallback/yanki")
    public Mono<Map<String, Object>> yankiFallback() {
        return Mono.just(buildResponse("yanki-service"));
    }

    @RequestMapping("/fallback/bootcoin")
    public Mono<Map<String, Object>> bootcoinFallback() {
        return Mono.just(buildResponse("bootcoin-service"));
    }

    @RequestMapping("/fallback/auth")
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
