package kroryi.spring.dto;

import kroryi.spring.entity.Member;
import lombok.*;

import java.io.Serializable;

/**
 * DTO for {@link Member}
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Getter
public class MemberDto implements Serializable {
    Long id;
    String email;
    String name;
    String nickname;
    String password;
    String role;
    String oauthType;
}