package org.project.idpclient;

import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpHeaders;


import java.util.HashMap;
import java.util.Map;

@Controller
public class LoginController {

    private final RestTemplate restTemplate;

    public LoginController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    // serve login page
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    // handle login attempt by sending request to IDP server
    @PostMapping("/login")
    public String handleLogin(String username, String password, Model model) {
        // Prepare request for IDP server
        String idpLoginUrl = "http://localhost:8080/login";
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/json");

        Map<String, String> body = new HashMap<>();
        body.put("username", username);
        body.put("password", password);

        HttpEntity<Map<String, String>> request = new HttpEntity<>(body, headers);

        try {
            // Call IDP server for login
            ResponseEntity<String> response = restTemplate.postForEntity(idpLoginUrl, request, String.class);

            String jwtToken = response.getBody();
            model.addAttribute("jwt", jwtToken); // add JWT to secured page model (thymeleaf can access)
            return "redirect:/secured";

        } catch (Exception e) {
            model.addAttribute("error", "Invalid credentials");
            return "login";
        }
    }

}
