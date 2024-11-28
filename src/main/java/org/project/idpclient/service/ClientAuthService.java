package org.project.idpclient.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class ClientAuthService {

    @Value("${idp.token-url}")
    private String tokenUrl;

    @Value("${idp.client-id}")
    private String clientId;

    @Value("${idp.client-secret}")
    private String clientSecret;

    private final RestTemplate restTemplate;

    public ClientAuthService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String fetchTokenFromIdp() {
        Map<String, String> payload = Map.of(
                "clientId", clientId,
                "clientSecret", clientSecret
        );

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        HttpEntity<Map<String, String>> entity = new HttpEntity<>(payload, headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                tokenUrl,
                HttpMethod.POST,
                entity,
                Map.class
        );

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            return (String) response.getBody().get("token");
        } else {
            throw new RuntimeException("Failed to fetch token from IDP: " + response.getStatusCode());
        }
    }
}
