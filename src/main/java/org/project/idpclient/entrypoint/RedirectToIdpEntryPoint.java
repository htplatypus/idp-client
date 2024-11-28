package org.project.idpclient.entrypoint;

import jakarta.security.auth.message.ClientAuth;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.project.idpclient.service.ClientAuthService;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class RedirectToIdpEntryPoint implements AuthenticationEntryPoint {

    private static final String IDP_LOGIN_URL = "https://localhost:8443/api/login";
    private final ClientAuthService clientAuthService;

    public RedirectToIdpEntryPoint(ClientAuthService clientAuthService) {
        this.clientAuthService = clientAuthService;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, IOException {

        String originalUrl = "https://localhost:8444/secured";
        String redirectUrl = "https://localhost:8443/api/login?redirect_uri=" + originalUrl;

        response.sendRedirect(redirectUrl);
    }
}
