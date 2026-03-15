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
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;

import java.util.Map;
import java.util.stream.Stream;

/**
 * Keycloak User Storage SPI 구현체
 *
 * Keycloak이 외부 사용자 저장소(DB)와 연동할 때 호출하는 진입점이다.
 * - 사용자 조회
 * - 로그인 시 비밀번호 검증
 * - 사용자 검색
 *
 * 회원가입/비밀번호 변경은 Spring 서버에서 별도로 처리한다.
 */


public class FcUserStorageProvider implements
        UserStorageProvider,       // 가장 기본 뼈대다. Provider 생명주기 쪽 인터페이스임
        UserLookupProvider,        // Keycloak 이 사용자를 찾을 때 호출하는 Provider
//        UserRegistrationProvider,// 회원 가입 처리는 Spring 에서처리
        CredentialInputValidator  // 비밀번호가 맞는지 검증하는 것
//        CredentialInputUpdater,  // 비밀번호 변경 (이것도 스프링에서 처리할 것)
//        UserQueryProvider          // 사용자 검색 (쿼리)
    {

    private final KeycloakSession session; // 키클락 내부 컨텍스트
    private final ComponentModel model;    // User Storage Provider
    private final UserRepository userRepository;

    public FcUserStorageProvider(KeycloakSession session,
                                 ComponentModel model,
                                 UserRepository userRepository) {
        this.session = session;
        this.model = model;
        this.userRepository = userRepository;
    }

    /** Provider 생명 주기상 들어가는 기본 메서드 */
    @Override
    public void close() {
    }

    /** 1. Keycloak 내부의 id 를 받기
     *  2. StorageId.externalId 로 내 DB 원본 id 추출하기
     *  3. Long 타입으로 변환 후 쿼리 날려서 DB에 있는 User 찾기
     *  4. UserModel 로 반환*/
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

    /** 로그인 할 때 필요함 !
     *  로그인시 사용된 userId 를 통해서 DB에 있는 User 찾기 */
    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        return userRepository.findByUserId(username)
                .map(user -> new FcUserAdapter(session, realm, model, user, userRepository))
                .orElse(null);
    }

    /**
     * 이메일을 통해 로그인, 검색 사용 안하기 때문에 null 반환
     */
    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        return null;
    }

    /**
     * password credential 반 처리 (String 타입으로만 처리함)
     * OTP, WebAuth 등등은 처리 x
     */
    @Override
    public boolean supportsCredentialType(String credentialType) {
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    /**
     * 로그인 가능한지 상태를 판단 ( 로그인을 시켜주진 않음 )
     * 1. 타입이 String 이 맞는지 검증
     * 2. 우리가 사용하는 FcUserAdapter의 유저가 맞는지
     * 3. DB의 password 가 비어있는지 확인
     * 다 통과 된다면, True로 반환 (로그인 시도 가능하다!)
     */
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


    /**
     * 실제 비밀번호 검증
     * 1. 타입이 맞는지 확인 (Password)
     * 2. 들어온 사용자 비밀번호 꺼내봄
     * 3. 들어온 사용자 username (user_id) 꺼내봄
     * 4. DB에서 해당 user_id 로 객체 조회
     * 5. user 에서 암호화되어있는 비밀번호 꺼내옴
     * 6. 만들어준 PasswordUtil 로 비밀번호 비교 함
     * 7. 맞다면 T / 틀리면 F 로 로그인 검증!
     */
    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {

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

//        System.err.println("username = " + username);
//        System.err.println("encodedPassword = " + encodedPassword);

        if (encodedPassword == null || encodedPassword.isBlank()) {
            return false;
        }

        //        System.err.println("matched = " + matched);

        return PasswordUtil.matches(rawPassword, encodedPassword);
    }


    /** 사용자 검색도 일단은 구현x 별도로 스프링에서 구현하거나 안 씀 */

//    @Override
//    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
//        return Stream.empty();
//    }
//
//    @Override
//    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
//        if ("username".equals(attrName) || "userId".equals(attrName)) {
//            return userRepository.findByUserId(attrValue).stream()
//                    .map(user -> new FcUserAdapter(session, realm, model, user, userRepository));
//        }
//        return Stream.empty();
//    }
//
//    @Override
//    public Stream<UserModel> searchForUserStream(RealmModel realm,
//                                                 Map<String, String> params,
//                                                 Integer firstResult,
//                                                 Integer maxResults) {
//        String search = params.get(UserModel.SEARCH);
//        if (search != null && !search.isBlank()) {
//            return searchForUserStream(realm, search, firstResult, maxResults);
//        }
//
//        String username = params.get(UserModel.USERNAME);
//        if (username != null && !username.isBlank()) {
//            return userRepository.findByUserIdContaining(username, firstResult, maxResults).stream()
//                    .map(user -> new FcUserAdapter(session, realm, model, user, userRepository));
//        }
//
//        String email = params.get(UserModel.EMAIL);
//        if (email != null && !email.isBlank()) {
//            return Stream.empty(); // 이메일 검색 지원 안하면 빈 스트림
//        }
//
//        // 필터가 없으면 전체 조회
//        return userRepository.findAll(firstResult, maxResults).stream()
//                .map(user -> new FcUserAdapter(session, realm, model, user, userRepository));
//    }


    /** 비밀번호 변경도 스프링에서 처리 (마이페이지 사용 예정) */
//    @Override
//    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
//        if (!supportsCredentialType(input.getType())) {
//            return false;
//        }
//
//        if (!(user instanceof FcUserAdapter adapter)) {
//            return false;
//        }
//
//        String rawPassword = input.getChallengeResponse();
//        if (rawPassword == null || rawPassword.isBlank()) {
//            return false;
//        }
//
//        rawPassword = PasswordUtil.encode(rawPassword);
//
//        // BCrypt 해시 적용
//        userRepository.updatePassword(adapter.getUserEntity().getId(), rawPassword);
//        adapter.getUserEntity().setPassword(rawPassword);
//
//        return true;
//    }
//
//    @Override
//    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
//    }

//    @Override
//    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
//        return Stream.empty();
//    }

    /** 회원가입은 Spring server 에서 별도 진행 */
//    @Override
//    public UserModel addUser(RealmModel realm, String username) {
//        if (userRepository.existsByUserId(username)) {
//            throw new IllegalStateException("이미 존재하는 userId 입니다.");
//        }
//
//        UserEntity user = new UserEntity();
//        user.setUserId(username);
//        user.setRole("USER");
//        user.setPoints(0);
//        user.setCreatedAt(LocalDateTime.now());
//        user.setUpdatedAt(LocalDateTime.now());
//
//        UserEntity savedUser = userRepository.save(user);
//        return new FcUserAdapter(session, realm, model, savedUser, userRepository);
//    }

    /** 회원 삭제는 처리 x */
//    @Override
//    public boolean removeUser(RealmModel realm, UserModel user) {
//        return false;
//    }

    /** 유저 수 카운터도 불 필요 */
//    @Override
//    public int getUsersCount(RealmModel realm) {
//        return userRepository.countAll();
//    }

}