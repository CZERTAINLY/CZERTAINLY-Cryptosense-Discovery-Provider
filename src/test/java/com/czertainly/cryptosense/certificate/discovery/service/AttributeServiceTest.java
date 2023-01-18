package com.czertainly.cryptosense.certificate.discovery.service;

import com.czertainly.api.model.client.attribute.RequestAttributeDto;
import com.czertainly.api.model.common.attribute.v2.BaseAttribute;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Arrays;
import java.util.List;

@SpringBootTest
public class AttributeServiceTest {
    @Autowired
    private AttributeService attributeService;

    private List<RequestAttributeDto> attributes;

    @BeforeEach
    protected void setup() {
        RequestAttributeDto apiUrl = new RequestAttributeDto();
        apiUrl.setUuid("1b6c48ad-c1c7-4c82-91ef-3e61bc9f52ac");
        apiUrl.setContent(List.of(new StringAttributeContent("https://analyzer.cryptosense.com/api/v2")));
        apiUrl.setName("apiUrl");

        RequestAttributeDto credentialKind = new RequestAttributeDto();
        apiUrl.setUuid("9379ca2c-aa51-42c8-8afd-2a2d16c99c56");
        //apiUrl.setContent(null);
        apiUrl.setName("credentialKind");

        attributes = Arrays.asList(apiUrl, credentialKind);
    }

    @Test
    public void testAttributeResponse() {
        List<BaseAttribute> attributes = attributeService.getAttributes("Cryptosense");
        Assertions.assertNotNull(attributes);
    }

    @Test
    public void testValidateAttributes_Fail() {
        Assertions.assertThrows(NullPointerException.class, () -> attributeService.validateAttributes("default", attributes));
    }
}
