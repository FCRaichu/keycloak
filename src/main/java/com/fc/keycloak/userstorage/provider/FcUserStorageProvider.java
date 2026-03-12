package com.fc.keycloak.userstorage.provider;

import com.fc.keycloak.userstorage.model.UserEntity;
import com.fc.keycloak.userstorage.repository.UserRepository;
import com.fc.keycloak.userstorage.util.PasswordUtil;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

import java.time.LocalDateTime;
import java.util.stream.Stream;

/**
 * 따지자며 Service 레이어
 *
 * UserLookupProvider -> 사용자 찾기
 * CredentialInputValidator -> 비밀번호 검증
 * CredentialInputUpdater -> 비밀번호 저장/변경
 *
 * 강상민 : ISFJ
 * 김예은 : ESFJ
 */


public class FcUserStorageProvider implements
        UserStorageProvider,
        UserLookupProvider,
        UserRegistrationProvider,
        CredentialInputValidator,
        CredentialInputUpdater {

    private final KeycloakSession session;
    private final ComponentModel model;
    private final UserRepository userRepository;

    public FcUserStorageProvider(KeycloakSession session,
                                 ComponentModel model,
                                 UserRepository userRepository) {
        this.session = session;
        this.model = model;
        this.userRepository = userRepository;
    }

    @Override
    public void close() {
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        String externalId = StorageId.externalId(id);
        if (externalId == null) {
            return null;
        }

        try {
            Long userId = Long.valueOf(externalId);
            return userRepository.findById(userId)
                    .map(user -> new FcUserAdapter(session, realm, model, user, userRepository))
                    .orElse(null);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        return userRepository.findByUserId(username)
                .map(user -> new FcUserAdapter(session, realm, model, user, userRepository))
                .orElse(null);
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        return null;
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        if (userRepository.existsByUserId(username)) {
            throw new IllegalStateException("이미 존재하는 userId 입니다.");
        }

        UserEntity user = new UserEntity();
        user.setUserId(username);
        user.setRole("USER");
        user.setPoints(0);
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());

        UserEntity savedUser = userRepository.save(user);
        return new FcUserAdapter(session, realm, model, savedUser, userRepository);
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType)) {
            return false;
        }

        if (!(user instanceof FcUserAdapter adapter)) {
            return false;
        }

        String password = adapter.getUserEntity().getPassword();
        return password != null && !password.isBlank();
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        System.err.println("=== isValid 호출됨 ===");

        if (!supportsCredentialType(input.getType())) {
            return false;
        }

        String rawPassword = input.getChallengeResponse();
        if (rawPassword == null || rawPassword.isBlank()) {
            return false;
        }

        String username = user.getUsername();
        if (username == null || username.isBlank()) {
            return false;
        }

        UserEntity foundUser = userRepository.findByUserId(username)
                .orElse(null);

        if (foundUser == null) {
            System.err.println("DB 사용자 없음: " + username);
            return false;
        }

        String encodedPassword = foundUser.getPassword();

        System.err.println("username = " + username);
        System.err.println("encodedPassword = " + encodedPassword);

        if (encodedPassword == null || encodedPassword.isBlank()) {
            return false;
        }

        boolean matched = PasswordUtil.matches(rawPassword, encodedPassword);
        System.err.println("matched = " + matched);

        return matched;
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) {
            return false;
        }

        if (!(user instanceof FcUserAdapter adapter)) {
            return false;
        }

        String rawPassword = input.getChallengeResponse();
        if (rawPassword == null || rawPassword.isBlank()) {
            return false;
        }

        rawPassword = PasswordUtil.encode(rawPassword);

        // BCrypt 해시 적용
        userRepository.updatePassword(adapter.getUserEntity().getId(), rawPassword);
        adapter.getUserEntity().setPassword(rawPassword);

        return true;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
        return Stream.empty();
    }


}