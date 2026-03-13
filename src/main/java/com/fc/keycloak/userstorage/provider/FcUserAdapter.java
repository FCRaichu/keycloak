package com.fc.keycloak.userstorage.provider;

import com.fc.keycloak.userstorage.model.UserEntity;
import com.fc.keycloak.userstorage.repository.UserRepository;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;

import java.util.*;

/**
 * Controller 같은 느낌
 */

public class FcUserAdapter extends AbstractUserAdapterFederatedStorage {

    private final UserEntity user;
    private final UserRepository userRepository;

    public FcUserAdapter(KeycloakSession session,
                         RealmModel realm,
                         ComponentModel model,
                         UserEntity user,
                         UserRepository userRepository) {
        super(session, realm, model);
        this.user = user;
        this.userRepository = userRepository;
    }

    @Override
    public String getUsername() {
        return user.getUserId();
    }

    @Override
    public void setUsername(String username) {
        user.setUserId(username);
    }

    @Override
    public String getFirstName() {
        return user.getNickname();
    }

    @Override
    public void setFirstName(String firstName) {
        user.setNickname(firstName);
        userRepository.updateNickname(user.getId(), firstName);
    }

    @Override
    public boolean isEnabled() {
        return user.getDeletedAt() == null;
    }

    @Override
    public String getId() {
        return StorageId.keycloakId(storageProviderModel, String.valueOf(user.getId()));
    }

    public UserEntity getUserEntity() {
        return user;
    }

    // user 에서 role 꺼내다 씀
    @Override
    protected Set<RoleModel> getRoleMappingsInternal() {
        Set<RoleModel> roles = new HashSet<>();

        String dbRole = user.getRole(); // "USER" or "ADMIN"

//        System.out.println("1. dbRole = " + dbRole); 디버깅 용도
        
        if (dbRole != null && !dbRole.isBlank()) {
            RoleModel roleModel = realm.getRole(dbRole);
//            System.out.println("roleModel != null ? roleModel.getName() = " + (roleModel != null ? roleModel.getName() : "null")); 디버깅 용도
            if (roleModel != null) {
                roles.add(roleModel);
            }
        }
        return roles;
    }

    // 기존 : Keycloak의 federated storage에 저장된 attribute 를 조회하는 방법
    // 변경 : DB 객체 user에서 직접 값을 꺼내서 반환하는 방법
    // fedreated storage -> 사용자 원본은 원래는 DB에 있지만, Keycloak 에서 추가로 관리하고 싶은 사용자 속성을 Keycloak 쪽 DB 에 따로 저장해둠
    @Override
    public String getFirstAttribute(String name) {
        if ("id".equals(name)) {
            return String.valueOf(user.getId()); // DB에서 Increment 로 설정해둔 PK 값
        }
        if ("userId".equals(name)) {
            return user.getUserId(); // 사용자 로그인 ID
        }

        if("nickname".equals(name)) {
            return user.getNickname();
        }
        return super.getFirstAttribute(name);
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        Map<String, List<String>> attributes = new HashMap<>(super.getAttributes());
        attributes.put("id", List.of(String.valueOf(user.getId())));
        attributes.put("userId", List.of(user.getUserId()));
        attributes.put("nickname", List.of(user.getNickname()));

        if (user.getNickname() != null && !user.getNickname().isBlank()) {
            attributes.put("firstName", List.of(user.getNickname()));
        }

        return attributes;
    }


}