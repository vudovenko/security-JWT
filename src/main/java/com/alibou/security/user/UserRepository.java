package com.alibou.security.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<SecurityUser, Integer> {

    Optional<SecurityUser> findByEmail(String email);
}
