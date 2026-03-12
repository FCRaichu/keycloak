package com.fc.keycloak.userstorage.repository;

import com.fc.keycloak.userstorage.model.UserEntity;

import java.util.List;
import java.util.Optional;

public interface UserRepository {

    Optional<UserEntity> findById(Long id);

    Optional<UserEntity> findByUserId(String userId);

    UserEntity save(UserEntity user);

    void updateNickname(Long id, String nickname);

    void updatePassword(Long id, String encodedPassword);

    boolean existsByUserId(String userId);

    boolean existsByNickname(String nickname);

    List<UserEntity> findAll(Integer firstResult, Integer maxResults);

    List<UserEntity> findByUserIdContaining(String keyword, Integer firstResult, Integer maxResults);

    int countAll();


}