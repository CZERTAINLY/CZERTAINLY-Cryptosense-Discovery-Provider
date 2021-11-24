package org.czertainly.cryptosense.certificate.discovery.service;

import com.czertainly.api.model.AttributeDefinition;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.Serializable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

@SpringBootTest
public class AttributeServiceTest {
    @Autowired
    private AttributeService attributeService;

    private List<AttributeDefinition> attributes;

    @BeforeEach
    private void setup(){
        AttributeDefinition apiUrl = new AttributeDefinition();
        apiUrl.setId("1b6c48ad-c1c7-4c82-91ef-3e61bc9f52ac");
        apiUrl.setValue("https://analyzer.cryptosense.com/api/v2");
        apiUrl.setName("apiUrl");

        AttributeDefinition credentialType = new AttributeDefinition();
        apiUrl.setId("9379ca2c-aa51-42c8-8afd-2a2d16c99c56");
        apiUrl.setValue(null);
        apiUrl.setName("credentialType");

        attributes = Arrays.asList(apiUrl, credentialType);
    }

    @Test
    public void testAttributeResponse() {
        List<AttributeDefinition> attributes = attributeService.getAttributes("IP-Hostname");
        Assertions.assertNotNull(attributes);
    }

    @Test
    public void testValidateAttributes_Fail() {
        Assertions.assertThrows(NullPointerException.class, () -> attributeService.validateAttributes("default",attributes));
    }
}
