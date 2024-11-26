package org.project.idpclient.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;

@Controller
@RequestMapping("/")
public class HomeController {

    private final RestTemplate restTemplate;

    public HomeController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping("/unsecured")
    public String unsecured() {
        return "unsecured";
    }

    @GetMapping("/secured")
    public String securedPage() {
        return "secured";
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {

        String idpLogoutUrl = "http://localhost:8080/api/auth/logout";
        restTemplate.postForEntity(idpLogoutUrl, null, Void.class); // post because csrf and get is supposed to be idempotent
        session.invalidate();

        return "redirect:/unsecured";
    }
}
