
package com.breizhcamp.demo.token;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
class TokenGenerator {

    private final SecretKey key;

    public TokenGenerator(@Value("${jwt.secret-key}") final String secretKey) {
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    public String generateToken(final boolean withExpiration, final boolean withSignature) {
        final JwtBuilder builder = Jwts.builder()
                .setSubject("pistolero")
                .claim("role", "shooter");

        if (withExpiration) {
            builder.setExpiration(new Date(System.currentTimeMillis() + 60 * 1000 * 3)); // 3 minutes
        }

        if (withSignature) {
            return builder.signWith(this.key).compact();
        } else {
            final String token = builder.signWith(this.key).compact();
            return token.substring(0, token.lastIndexOf('.') + 1); // strip signature
        }
    }
}
