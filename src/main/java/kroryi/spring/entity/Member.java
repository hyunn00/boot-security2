package kroryi.spring.entity;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "member")
@NoArgsConstructor
public class Member {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    private String email;
    private String name;
    private String nickname;
    private String password;
    private String role;

    @Column(name="oauth_type", columnDefinition = "VARCHAR(50)")
    private String oauthType;

    @Builder
    public Member(String email, String nickname, String oauthType) {
        this.email = email;
        this.nickname = nickname;
        this.oauthType = oauthType;
    }
}