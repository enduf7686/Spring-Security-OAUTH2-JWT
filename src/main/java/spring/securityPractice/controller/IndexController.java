package spring.securityPractice.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import spring.securityPractice.config.oauth.MemberDetails;
import spring.securityPractice.repository.MemberRepository;

@Slf4j
@Controller
@RequiredArgsConstructor
public class IndexController {

    private final MemberRepository memberRepository;

    @GetMapping("/test/login")
    @ResponseBody
    public String loginTest(@AuthenticationPrincipal MemberDetails memberDetails) {
        return "세션 정보 확인하기";
    }

    @GetMapping("/test/oauth/login")
    @ResponseBody
    public String loginOauthTest(@AuthenticationPrincipal OAuth2User oAuth2User) {
        log.info("authentication={}", oAuth2User.getAttributes());
        return "OAuth 세션 정보 확인하기";
    }

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/user")
    @ResponseBody
    public MemberDetails user(@AuthenticationPrincipal MemberDetails memberDetails) {
        return memberDetails;
    }

    @GetMapping("/admin")
    @ResponseBody
    public String admin() {
        return "admin";
    }

    @GetMapping("/manager")
    @ResponseBody
    public String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }
}

