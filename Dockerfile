FROM quay.io/keycloak/keycloak:26.5.5 AS builder

COPY build/libs/keycloak-0.0.1-SNAPSHOT.jar /opt/keycloak/providers/
COPY mysql-connector-j-9.6.0.jar /opt/keycloak/providers/
COPY spring-security-crypto-6.5.1.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.5.5
COPY --from=builder /opt/keycloak/ /opt/keycloak/

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
