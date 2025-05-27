package com.breizhcamp.demo.dpop;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Map;

@RestController
@RequestMapping("/proof-of-possession")
public class DPoPController {

    private final RSAKey key;
    private final DPoPGenerator dpopGenerator;

    public DPoPController(final DPoPGenerator dpopGenerator) throws IOException, ParseException {
        this.dpopGenerator = dpopGenerator;

        final ClassPathResource resource = new ClassPathResource("jwk.json");
        final String jwtContent = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8);
        this.key = RSAKey.parse(jwtContent);

    }

    @GetMapping("/valid")
    public Map<String, String> valid() throws Exception {
        final URI uri = new URI("http://localhost:8081/saloon");
        final String method = "GET";

        final String dpopProof = this.dpopGenerator.generateDPoPProof(uri, method, this.key);
        return Map.of(
                "token", dpopProof
        );
    }

    @GetMapping("/invalid-uri")
    public Map<String, String> invalidUri() throws Exception {
        final URI uri = new URI("http://localhost:8081/black-jack");
        final String method = "GET";

        final String dpopProof = this.dpopGenerator.generateDPoPProof(uri, method, this.key);
        return Map.of(
                "token", dpopProof
        );
    }

    @GetMapping("/invalid-method")
    public Map<String, String> invalidMethod() throws Exception {
        final URI uri = new URI("http://localhost:8081/saloon");
        final String method = "POST";

        final String dpopProof = this.dpopGenerator.generateDPoPProof(uri, method, this.key);
        return Map.of(
                "token", dpopProof
        );
    }
}
