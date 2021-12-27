package org.czertainly.cryptosense.certificate.discovery.service;

import com.czertainly.api.model.AttributeDefinition;
import com.czertainly.api.model.discovery.DiscoveryProviderDto;
import org.czertainly.cryptosense.certificate.discovery.dao.DiscoveryHistory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ActiveProfiles;

import javax.transaction.Transactional;
import java.util.Arrays;

@SpringBootTest
@Transactional
@Rollback
@ActiveProfiles(profiles = "non-async")
public class DiscoveryServiceTest {

    @Autowired
    private DiscoveryService discoveryService;

    private DiscoveryProviderDto discoveryProviderDtoTest;
    private DiscoveryHistory discoveryHistory;

    @BeforeEach
    public void setUp() {
        discoveryProviderDtoTest = new DiscoveryProviderDto();
        discoveryProviderDtoTest.setName("test123");
        discoveryProviderDtoTest.setConnectorUuid("123456");

        AttributeDefinition apiUrl = new AttributeDefinition();
        apiUrl.setUuid("1b6c48ad-c1c7-4c82-91ef-3e61bc9f52ac");
        apiUrl.setValue("https://analyzer.cryptosense.com/api/v2");
        apiUrl.setName("apiUrl");

        AttributeDefinition credentialKind = new AttributeDefinition();
        credentialKind.setUuid("9379ca2c-aa51-42c8-8afd-2a2d16c99c56");
        credentialKind.setValue(null);
        credentialKind.setName("credentialKind");
        discoveryProviderDtoTest.setAttributes(Arrays.asList(apiUrl, credentialKind));

        discoveryHistory = new DiscoveryHistory();
        discoveryHistory.setName("test");
    }

    @Test
    public void getProviderDtoDataTest(){
        Assertions.assertAll(() -> discoveryService.getProviderDtoData(discoveryProviderDtoTest, discoveryHistory));
    }

    @Test
    public void discoveryTest() {
        Assertions.assertAll(() -> discoveryService.discoverCertificate(discoveryProviderDtoTest, discoveryHistory));
    }
}
