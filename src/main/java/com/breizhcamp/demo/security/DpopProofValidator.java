package com.breizhcamp.demo.security;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class DpopProofValidator implements Filter {

    private final Set<String> usedJtis = ConcurrentHashMap.newKeySet();

    @Override
    public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain)
            throws IOException, ServletException {

        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        if (!request.getRequestURI().startsWith("/token") &&
                !request.getRequestURI().startsWith("/proof-of-possession")) {

            final String dpopProof = request.getHeader("DPoP");
            if (dpopProof == null) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Missing DPoP header");
                return;
            }

            try {
                // Parse the JWT without verifying yet
                final SignedJWT signedJWT = SignedJWT.parse(dpopProof);
                final JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

                // Step 1: Validate 'htm', 'htu', 'iat', 'jti'
                final String htm = claims.getStringClaim("htm");
                final String htu = claims.getStringClaim("htu");
                final String jti = claims.getStringClaim("jti");
                final Date iat = claims.getIssueTime();

                if (!request.getMethod().equalsIgnoreCase(htm)) {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid HTTP method in DPoP proof");
                }
                if (!request.getRequestURL().toString().equalsIgnoreCase(htu)) {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid HTTP URI in DPoP proof");
                }
                if (iat == null || Math.abs(Instant.now().getEpochSecond() - iat.toInstant().getEpochSecond()) > 300) { // 5 minutes
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "DPoP proof is too old or too far in the future");
                }
                if (!this.usedJtis.add(jti)) {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "DPoP proof replayed");
                }

                // Step 2: Verify signature
                final JWK jwk = JWK.parse(signedJWT.getHeader().getJWK().toJSONObject());
                final JWSVerifier verifier = new RSASSAVerifier(((RSAKey) jwk).toRSAPublicKey());
                if (!signedJWT.verify(verifier)) {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid DPoP signature");
                }

                // - Optionally match `cnf.jkt` from access token with DPoP proof key

            } catch (final Exception e) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid DPoP token");
                return;
            }
        }

        chain.doFilter(req, res);
    }
}
