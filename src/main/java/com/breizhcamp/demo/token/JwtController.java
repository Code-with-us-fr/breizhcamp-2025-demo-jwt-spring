
package com.breizhcamp.demo.token;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/token")
class JwtController {

    private final TokenGenerator tokenGenerator;

    public JwtController(final TokenGenerator tokenGenerator) {
        this.tokenGenerator = tokenGenerator;
    }

    @GetMapping("/no-signature")
    public Map<String, String> noSignature() {
        final String token = this.tokenGenerator.generateToken(false, false);
        return Map.of("token", token);
    }

    @GetMapping("/with-expiration")
    public Map<String, String> withExpiration() {
        final String token = this.tokenGenerator.generateToken(true, false);
        return Map.of("token", token);
    }

    @GetMapping("/with-expiration-and-signature")
    public Map<String, String> withSignature() {
        final String token = this.tokenGenerator.generateToken(true, true);
        return Map.of("token", token);
    }
}
