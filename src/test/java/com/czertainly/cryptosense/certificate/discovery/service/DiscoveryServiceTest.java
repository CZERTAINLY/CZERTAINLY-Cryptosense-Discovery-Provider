package com.czertainly.cryptosense.certificate.discovery.service;

import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.connector.discovery.DiscoveryDataRequestDto;
import com.czertainly.api.model.connector.discovery.DiscoveryRequestDto;
import com.czertainly.cryptosense.certificate.discovery.dao.DiscoveryHistory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ActiveProfiles;

import jakarta.transaction.Transactional;
import java.util.Arrays;
import java.util.List;

@SpringBootTest
@Transactional
@Rollback
@ActiveProfiles(profiles = "non-async")
public class DiscoveryServiceTest {

    @Autowired
    private DiscoveryService discoveryService;

    private DiscoveryRequestDto discoveryProviderDtoTest;
    private DiscoveryDataRequestDto discoveryProviderDtoTestExists;
    private DiscoveryHistory discoveryHistory;

    @BeforeEach
    public void setUp() {
        discoveryProviderDtoTest = new DiscoveryRequestDto();
        discoveryProviderDtoTest.setName("test123");

        discoveryProviderDtoTestExists = new DiscoveryDataRequestDto();
        discoveryProviderDtoTestExists.setName("test123");
        discoveryProviderDtoTestExists.setPageNumber(0);
        discoveryProviderDtoTestExists.setItemsPerPage(100);


        RequestAttributeDto apiUrl = new RequestAttributeDto();
        apiUrl.setUuid("1b6c48ad-c1c7-4c82-91ef-3e61bc9f52ac");
        apiUrl.setContent(List.of(new StringAttributeContent("https://analyzer.cryptosense.com/api/v2")));
        apiUrl.setName("apiUrl");

        RequestAttributeDto credentialKind = new RequestAttributeDto();
        credentialKind.setUuid("9379ca2c-aa51-42c8-8afd-2a2d16c99c56");
        //credentialKind.setContent(null);
        credentialKind.setName("credentialKind");
        discoveryProviderDtoTest.setAttributes(Arrays.asList(apiUrl, credentialKind));

        discoveryHistory = new DiscoveryHistory();
        discoveryHistory.setName("test");
    }

    @Test
    public void getProviderDtoDataTest() {
        Assertions.assertAll(() -> discoveryService.getProviderDtoData(discoveryProviderDtoTestExists, discoveryHistory));
    }

    @Test
    public void discoveryTest() {
        Assertions.assertAll(() -> discoveryService.discoverCertificate(discoveryProviderDtoTest, discoveryHistory));
    }
}
