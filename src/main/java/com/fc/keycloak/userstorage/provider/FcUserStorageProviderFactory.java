package com.fc.keycloak.userstorage.provider;

import com.fc.keycloak.userstorage.config.DataSourceProvider;
import com.fc.keycloak.userstorage.repository.JdbcUserRepository;
import com.fc.keycloak.userstorage.repository.UserRepository;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.storage.UserStorageProviderFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.List;

/**
 * Keycloak -> DB 연동
 * 	1.	Keycloak에 "fc-user-storage" 라는 사용자 저장소 Provider를 등록
 * 	2.	관리자 화면에서 설정할 항목(DB URL, 계정, 비밀번호)을 정의
 * 	3.	저장된 설정값으로 DataSource, UserRepository 생성
 * 	4.	최종적으로 FcUserStorageProvider 객체를 만들어 Keycloak에 넘김
 * 	5.	설정 저장 전에 DB 연결이 되는지 검증
 */

public class FcUserStorageProviderFactory implements UserStorageProviderFactory<FcUserStorageProvider> {

    public static final String PROVIDER_ID = "fc-user-storage";
    public static final String DB_URL = "dbUrl";
    public static final String DB_USERNAME = "dbUsername";
    public static final String DB_PASSWORD = "dbPassword";

    @Override
    public FcUserStorageProvider create(KeycloakSession session, ComponentModel model) {
        String dbUrl = model.getConfig().getFirst(DB_URL);
        String dbUsername = model.getConfig().getFirst(DB_USERNAME);
        String dbPassword = model.getConfig().getFirst(DB_PASSWORD);

        DataSource dataSource = DataSourceProvider.create(dbUrl, dbUsername, dbPassword);
        UserRepository userRepository = new JdbcUserRepository(dataSource);

        return new FcUserStorageProvider(session, model, userRepository);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getHelpText() {
        return "FC Seoul Archive users 테이블과 연동하는 사용자 저장소";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty dbUrl = new ProviderConfigProperty();
        dbUrl.setName(DB_URL);
        dbUrl.setLabel("Database URL");
        dbUrl.setType(ProviderConfigProperty.STRING_TYPE);
        dbUrl.setHelpText("예: jdbc:mysql://host:3306/dbname?serverTimezone=Asia/Seoul");

        ProviderConfigProperty dbUsername = new ProviderConfigProperty();
        dbUsername.setName(DB_USERNAME);
        dbUsername.setLabel("Database Username");
        dbUsername.setType(ProviderConfigProperty.STRING_TYPE);
        dbUsername.setHelpText("DB 접속 계정");

        ProviderConfigProperty dbPassword = new ProviderConfigProperty();
        dbPassword.setName(DB_PASSWORD);
        dbPassword.setLabel("Database Password");
        dbPassword.setType(ProviderConfigProperty.PASSWORD);
        dbPassword.setHelpText("DB 접속 비밀번호");

        return List.of(dbUrl, dbUsername, dbPassword);
    }

    @Override
    public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config) {
        String dbUrl = config.getConfig().getFirst(DB_URL);
        String dbUsername = config.getConfig().getFirst(DB_USERNAME);
        String dbPassword = config.getConfig().getFirst(DB_PASSWORD);

        if (dbUrl == null || dbUrl.isBlank()) {
            throw new ComponentValidationException("dbUrl은 필수입니다.");
        }
        if (dbUsername == null || dbUsername.isBlank()) {
            throw new ComponentValidationException("dbUsername은 필수입니다.");
        }
        if (dbPassword == null || dbPassword.isBlank()) {
            throw new ComponentValidationException("dbPassword는 필수입니다.");
        }

        try {
            DataSource dataSource = DataSourceProvider.create(dbUrl, dbUsername, dbPassword);
            try (Connection ignored = dataSource.getConnection()) {
                // 연결 확인만 수행
            }
        } catch (Exception e) {
            throw new ComponentValidationException("DB 연결 실패: " + e.getMessage(), e);
        }

    }
}