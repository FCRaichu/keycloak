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

/** 키클락에서 Username, FirstName 등을 읽어도 내 DB에 있는 객체를 반환하기 위해 변환하는 어댑터! */

public class FcUserAdapter extends AbstractUserAdapterFederatedStorage {

    private final UserEntity user;
    private final UserRepository userRepository;

    public FcUserAdapter(KeycloakSession session, // 키클락 내부 컨텍스트
                         RealmModel realm,        // 어느 Realm 의 사용자인지
                         ComponentModel model,    // User Storage Provider 설정 정보
                         UserEntity user,         // 내가 만든 User 객체
                         UserRepository userRepository) { // 내가 만든 UserRepository
        super(session, realm, model);
        this.user = user;
        this.userRepository = userRepository;
    }

    /** 키클락의 Username -> UserId 로 변환 */
    @Override
    public String getUsername() {
        return user.getUserId();
    }

    @Override
    public void setUsername(String username) {
        user.setUserId(username);
    }

    /** 키클락의 (FirstName, LastName) 이 있지만 FirstName만 사용할 것이고 -> Nickname 으로 변환 */
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

    /** 단순하게 우리 user.id 만 반환하는 것이 아닌
     *  DB의 사용자 id를 “이 사용자는 이 provider 소속의 외부 사용자다”라는 정보까지 포함한 Keycloak 전용 사용자 id로 변환
     *  여기 개념이 조금 어렵다.! */
    @Override
    public String getId() {
        return StorageId.keycloakId(storageProviderModel, String.valueOf(user.getId()));
    }

    /** 나의 DB의 UserEntity */
    public UserEntity getUserEntity() {
        return user;
    }


    /** 우리 DB의 user.role 값을 꺼내서, Keycloak이 사용하는 UserModel의 role mapping으로 변환 */
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
    // 변경 : DB 객체 user에서 직접 값을 꺼내서 반환하는 방법 (딱 하나!)
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

    /** 여기서 claim 에 id, userId, nicname, role 올릴 수 있음! */
    // 기존 : Keycloak의 federated storage에 저장된 attribute 를 조회하는 방법
    // 변경 : DB 객체 user에서 직접 값을 꺼내서 반환하는 방법 (전부 !!)
    // fedreated storage -> 사용자 원본은 원래는 DB에 있지만, Keycloak 에서 추가로 관리하고 싶은 사용자 속성을 Keycloak 쪽 DB 에 따로 저장해둠
    @Override
    public Map<String, List<String>> getAttributes() {
        Map<String, List<String>> attributes = new HashMap<>(super.getAttributes());
        attributes.put("id", List.of(String.valueOf(user.getId())));
        attributes.put("userId", List.of(user.getUserId()));
        attributes.put("nickname", List.of(user.getNickname()));
        attributes.put("role", List.of(user.getRole()));

        if (user.getNickname() != null && !user.getNickname().isBlank()) {
            attributes.put("firstName", List.of(user.getNickname()));
        }

        return attributes;
    }


}