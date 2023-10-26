package spring.securityPractice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import spring.securityPractice.config.oauth.MemberDetailsService;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final MemberDetailsService memberDetailsService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .sessionManagement(
                        session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .requestCache(
                        request -> request.requestCache(new CookieRequestCache())
                )
                .authorizeRequests(
                        authorize -> authorize
                                .antMatchers("/user/**").authenticated() /** 인증만 되면 들어갈 수 있는 주소 **/
                                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
                                .anyRequest().permitAll()
                )
                .addFilterBefore(jwtAuthenticationFilter(), OAuth2LoginAuthenticationFilter.class)
                .oauth2Login(
                        oauth2 -> oauth2
                                .loginPage("/loginForm")
                                .defaultSuccessUrl("/")
                                .tokenEndpoint(
                                        token -> token.accessTokenResponseClient(instagramAccessTokenResponseClient())
                                )
                                .userInfoEndpoint(userInfo -> userInfo.userService(memberDetailsService))
                                .successHandler(customSuccessHandler())
                );

        return http.build();
    }

    @Bean
    public InstagramAccessTokenResponseClient instagramAccessTokenResponseClient() {
        return new InstagramAccessTokenResponseClient();
    }

    @Bean
    public AuthenticationSuccessHandler customSuccessHandler() {
        return new SavedRequestAwareAndJwtResponseSuccessHandler();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }
}
