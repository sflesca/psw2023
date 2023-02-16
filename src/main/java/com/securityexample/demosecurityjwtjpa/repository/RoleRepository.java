package com.securityexample.demosecurityjwtjpa.repository;

import com.securityexample.demosecurityjwtjpa.models.ERole;
import com.securityexample.demosecurityjwtjpa.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
