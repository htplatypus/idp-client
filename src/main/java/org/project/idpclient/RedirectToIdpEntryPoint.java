package org.project.idpclient;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class RedirectToIdpEntryPoint implements AuthenticationEntryPoint {

    private static final String IDP_LOGIN_URL = "http://localhost:8080/api/login";

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, IOException {

        String originalUrl = "http://localhost:8081/secured";
        String redirectUrl = IDP_LOGIN_URL + "?redirect_uri=" + originalUrl;

        // redirect to idp login page
        response.sendRedirect(redirectUrl);
    }
}
