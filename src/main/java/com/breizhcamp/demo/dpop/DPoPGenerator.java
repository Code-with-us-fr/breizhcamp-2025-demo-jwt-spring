package com.breizhcamp.demo.dpop;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Component
public class DPoPGenerator {

    /**
     * Generates a DPoP proof JWT.
     *
     * @param uri    The URI the request is being made to
     * @param method The HTTP method (e.g. GET, POST)
     * @param rsaJwk The RSA JWK (with private key)
     * @return A signed DPoP JWT
     */
    public String generateDPoPProof(final URI uri, final String method, final RSAKey rsaJwk) throws Exception {

        final Instant now = Instant.now();

        final JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())         // jti
                .issueTime(Date.from(now))                   // iat
                .claim("htu", uri.toString())                // htu
                .claim("htm", method.toUpperCase())          // htm
                .build();

        final JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(new JOSEObjectType("dpop+jwt"))
                .jwk(rsaJwk.toPublicJWK())
                .build();

        final SignedJWT signedJWT = new SignedJWT(header, claims);

        final JWSSigner signer = new RSASSASigner(rsaJwk.toPrivateKey());
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }
}


