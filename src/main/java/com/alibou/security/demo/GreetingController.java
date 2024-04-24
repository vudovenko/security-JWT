package com.alibou.security.demo;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller()
@RequestMapping("/api/v1/greeting-controller")
public class GreetingController {

    @GetMapping
    public String getGreeting() {
        return "/greeting";
    }
}
