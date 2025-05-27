package com.breizhcamp.demo.saloon;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;

@RestController
@RequestMapping("/saloon")
class SaloonController {

    @GetMapping
    public String haveADrink(@RequestHeader(value = "Authorization", required = false) final String authorizationHeader) {
        try {
            final String token = extractToken(authorizationHeader);

            final Jwt<Header, Claims> jwt = Jwts.parserBuilder()
                    .build()
                    .parseClaimsJwt(token);
            final Claims claims = jwt.getBody();

            final Date exp = claims.getExpiration();
            if (exp == null || exp.before(new Date())) {
                return "⏰ Token expiré";
            }

            return "✅ Accès autorisé ! Bonjour " + claims.getSubject() + " \uD83E\uDD20, j'ai un bourbon 12 ans d'âge, tu m'en diras des nouvelles !";

        } catch (final ExpiredJwtException e) {
            throw new AccessDeniedException("⏰ Token expiré", e);
        } catch (final UnsupportedJwtException | MalformedJwtException | SignatureException e) {
            throw new AccessDeniedException("❌ Token invalide : " + e.getMessage(), e);
        }
    }

    private String extractToken(final String header) {
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        throw new AccessDeniedException("Authorization header manquant ou mal formé");
    }
}
