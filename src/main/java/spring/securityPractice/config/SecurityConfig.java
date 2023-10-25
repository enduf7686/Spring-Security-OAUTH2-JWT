package spring.securityPractice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import spring.securityPractice.config.oauth.MemberOauth2UserService;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final MemberOauth2UserService memberOauth2UserService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .sessionManagement(
                        session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
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
                                .defaultSuccessUrl("/user")
                                .tokenEndpoint(
                                        token -> token.accessTokenResponseClient(instagramAccessTokenResponseClient()))
                                .userInfoEndpoint(userInfo -> userInfo.userService(memberOauth2UserService))
                                .successHandler(customSuccessHandler())
                );

        return httpSecurity.build();
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
