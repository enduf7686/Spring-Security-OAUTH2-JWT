package spring.securityPractice.config.security;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

@Getter
@RequiredArgsConstructor
public class MemberDetails implements OAuth2User {

    private final Long id;

    private final String username;

    private final String role;

    private final String providerId;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(() -> String.valueOf(role));
        return authorities;
    }

    @Override
    public String getName() {
        return username + "_" + providerId;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return null;
    }
}
