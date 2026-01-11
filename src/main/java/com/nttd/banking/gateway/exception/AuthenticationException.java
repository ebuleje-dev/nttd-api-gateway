package com.nttd.banking.gateway.exception;

/**
 * Custom exception for authentication failures.
 *
 * @author NTT Data Banking Team
 * @since 1.0.0
 */
public class AuthenticationException extends RuntimeException {

    /**
     * Constructor with message.
     *
     * @param message the error message
     */
    public AuthenticationException(String message) {
        super(message);
    }

    /**
     * Constructor with message and cause.
     *
     * @param message the error message
     * @param cause the cause of the exception
     */
    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
