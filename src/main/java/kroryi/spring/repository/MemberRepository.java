package kroryi.spring.repository;

import kroryi.spring.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByEmailAndOauthType(String email, String oauthType);

    Optional<Member> findMemberByEmail(String email);
}
