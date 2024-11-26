package org.project.idpclient.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AppConfig {

    // define rest template bean for sending requests to rest apis
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
