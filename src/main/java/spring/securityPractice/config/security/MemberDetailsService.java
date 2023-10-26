package spring.securityPractice.config.security;

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
public class MemberDetailsService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        String userInfoRequestUri = getUserInfoRequestUri(userRequest);
        ResponseEntity<Map> response = sendInstagramUserInfoRequest(userInfoRequestUri);

        Map<String, String> userInfo = response.getBody();
        userInfo.put("userId", userRequest.getAdditionalParameters().get("userId").toString());

        Member member = getMemberFromUserInfo(userInfo);
        return createMemberDetails(member);
    }

    private String getUserInfoRequestUri(OAuth2UserRequest userRequest) {
        String accessToken = userRequest
                .getAccessToken()
                .getTokenValue();

        return userRequest
                .getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUri()
                .replace("{accessToken}", accessToken);
    }

    private ResponseEntity<Map> sendInstagramUserInfoRequest(String userInfoUri) {
        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<String> entity = new HttpEntity<>(new HttpHeaders());
        ResponseEntity<Map> response = restTemplate.exchange(userInfoUri, HttpMethod.GET, entity, Map.class);
        return response;
    }

    private Member getMemberFromUserInfo(Map<String, String> userInfo) {
        String username = "@" + userInfo.get("username");
        String providerId = userInfo.get("userId");

        Optional<Member> member = memberRepository.findByUsername(username);
        if (member.isEmpty()) {
            member = Optional.of(
                    memberRepository.save(Member.builder()
                            .username(username)
                            .password(UUID.randomUUID().toString())
                            .role(Role.ROLE_USER)
                            .provider("INSTAGRAM")
                            .providerId(providerId)
                            .createDate(LocalDateTime.now())
                            .build()));
        }
        return member.get();
    }

    private MemberDetails createMemberDetails(Member member) {
        return new MemberDetails(
                member.getId(),
                member.getUsername(),
                member.getRole().toString(),
                member.getProviderId()
        );
    }
}
