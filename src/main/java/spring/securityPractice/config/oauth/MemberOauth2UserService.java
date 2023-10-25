package spring.securityPractice.config.oauth;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import spring.securityPractice.domain.Member;
import spring.securityPractice.domain.Role;
import spring.securityPractice.repository.MemberRepository;

@Slf4j
@Component
@RequiredArgsConstructor
public class MemberOauth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        String userInfoUri = userRequest.getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri();
        userInfoUri = userInfoUri.replace("{accessToken}", userRequest.getAccessToken().getTokenValue());
        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<String> entity = new HttpEntity<>(new HttpHeaders());
        ResponseEntity<Map> response = restTemplate.exchange(userInfoUri, HttpMethod.GET, entity, Map.class);

        Map<String, String> userAttributes = response.getBody();

        String username = "@" + userAttributes.get("username");
        String userId = userRequest.getAdditionalParameters().get("userId").toString();

        Optional<Member> member = memberRepository.findByUsername(username);
        if (member.isEmpty()) {
            member = Optional.of(
                    memberRepository.save(Member.builder()
                            .username(username)
                            .password(UUID.randomUUID().toString())
                            .role(Role.ROLE_USER)
                            .provider("INSTAGRAM")
                            .providerId(userId)
                            .createDate(LocalDateTime.now())
                            .build()));
        }

        return new MemberDetails(member.get());
    }

    public MemberDetails loadUserByUsername(String username) {
        Optional<Member> member = memberRepository.findByUsername(username);
        return new MemberDetails(member.get());
    }
}
