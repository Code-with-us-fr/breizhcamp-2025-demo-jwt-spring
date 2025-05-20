package com.breizhcamp.demo;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_ABSENT;

@ControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(AccessDeniedException.class)
    public final ResponseEntity<ApiError> handleAccessDeniedException(final AccessDeniedException ex, final WebRequest request) {
        final ApiError errorDetails = new ApiError(ex.getMessage());
        return new ResponseEntity<>(errorDetails, HttpStatus.FORBIDDEN);
    }

    @JsonInclude(NON_ABSENT)
    record ApiError(String message) {
    }

}