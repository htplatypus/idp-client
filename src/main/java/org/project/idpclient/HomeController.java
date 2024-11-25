package org.project.idpclient;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/unsecured")
    public String unsecured() {
        return "unsecured";
    }

    @GetMapping("/secured")
    public String secured() {
        return "secured";
    }

}
