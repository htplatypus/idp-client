package org.project.idpclient.config;

import org.project.idpclient.filter.JwtSecurityFilter;
import org.project.idpclient.entrypoint.RedirectToIdpEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class SecurityConfig {

    // register jwt filter before username/password filer
    private final JwtSecurityFilter jwtSecurityFilter;
    // set auth custom entry point
    private final RedirectToIdpEntryPoint redirectToIdpEntryPoint;

    public SecurityConfig(JwtSecurityFilter jwtSecurityFilter, RedirectToIdpEntryPoint redirectToIdpEntryPoint) {
        this.jwtSecurityFilter = jwtSecurityFilter;
        this.redirectToIdpEntryPoint = redirectToIdpEntryPoint;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource())) // Enable CORS!!

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/unsecured/**").permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/api/logout").permitAll()
                        .requestMatchers("/static/**", "/css/**", "/js/**", "/images/**").permitAll()
                        .requestMatchers("/secured/**").authenticated()
                        .anyRequest().authenticated()
                )
                .logout(logout -> logout //configure spring sec logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/unsecured")
                        .invalidateHttpSession(true)
                        .deleteCookies("jwt")
                )
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(redirectToIdpEntryPoint) // set custom entry point
                )
                .addFilterBefore(jwtSecurityFilter, UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:8081")); // allow client
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS")); //allow pre-flight chrome requests  like OPTIONS
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        configuration.setExposedHeaders(List.of("Authorization"));
        configuration.setAllowCredentials(true); // allow cookies or credentials

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
