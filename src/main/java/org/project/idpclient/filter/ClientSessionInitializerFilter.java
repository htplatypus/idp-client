package org.project.idpclient.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.project.idpclient.service.ClientAuthService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class ClientSessionInitializerFilter extends OncePerRequestFilter {

    private final ClientAuthService clientAuthService;

    public ClientSessionInitializerFilter(ClientAuthService clientAuthService) {
        this.clientAuthService = clientAuthService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        HttpSession session = request.getSession(true); // Create a session if one doesn’t exist

        if (session.getAttribute("jwt-client") == null) {
            try {
                String token = clientAuthService.fetchTokenFromIdp();
                session.setAttribute("jwt-client", token);
                System.out.println("fetched token from IDP: " + token);
            } catch (Exception e) {
                System.out.println("failed to fetch token from IDP");
                throw new ServletException("failed to fetch token from IDP", e);
            }
        }

        filterChain.doFilter(request, response);
    }
}
