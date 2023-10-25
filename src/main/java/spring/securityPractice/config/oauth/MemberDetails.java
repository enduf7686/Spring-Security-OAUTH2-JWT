package spring.securityPractice.config.oauth;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import spring.securityPractice.domain.Member;

import java.util.*;

@Getter
@RequiredArgsConstructor
public class MemberDetails implements OAuth2User {

    private final Member member;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorityList = new ArrayList<>();
        authorityList.add(() -> member.getRole().toString());
        return authorityList;
    }

    @Override
    public Map<String, Object> getAttributes() {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("id", member.getId());
        attributes.put("name", member.getUsername());
        return attributes;
    }

    @Override
    public String getName() {
        return member.getUsername();
    }

    public Long getId() {
        return member.getId();
    }

    public String getRegistrationId() {
        return member.getProviderId();
    }
}
