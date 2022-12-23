package com.czertainly.cryptosense.certificate.discovery.service;

import com.czertainly.api.model.common.attribute.v2.DataAttribute;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContent;
import com.czertainly.api.model.common.attribute.v2.content.data.CredentialAttributeContentData;
import com.czertainly.cryptosense.certificate.discovery.dto.AnalyzerRequestDto;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;

import javax.transaction.Transactional;
import java.util.List;

@SpringBootTest
@Transactional
@Rollback
public class AnalyzerTest {

    @Autowired
    private AnalyzerService analyzerService;

    private WireMockServer mockServer;

    private CredentialAttributeContentData credDto;

    @BeforeEach
    public void setUp() {
        mockServer = new WireMockServer(3665);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        credDto = new CredentialAttributeContentData();
        credDto.setUuid("57fd083e-92c5-411c-964c-5b4e7fe35205");
        credDto.setName("test");

        DataAttribute apiKey = new DataAttribute();
        apiKey.setUuid("aac5c2d5-5dc3-4ddb-9dfa-3d76b99135f8");
        apiKey.setName("apiKey");
        apiKey.setContent(List.of(new StringAttributeContent("asdfEDssdfhcHJSHxhFxf")));
        credDto.setAttributes(List.of(apiKey));
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    public void testProjectList() {
        mockServer.stubFor(WireMock.post("/").willReturn(WireMock.okJson("{ \"data\": { \"viewer\": { \"organization\": { \"projects\": { \"edges\": [ { \"node\": { \"id\": \"UHJvamVjdDo4MDc=\", \"name\": \"Java Demo\", \"api\": \"JAVA\" } }, { \"node\": { \"id\": \"UHJvamVjdDo4MDg=\", \"name\": \"PKCS #11 Demo\", \"api\": \"PKCS11_FUZZING\" } }, { \"node\": { \"id\": \"UHJvamVjdDo4MTA=\", \"name\": \"Host scan project\", \"api\": \"HOST_SCANNER\" } } ] } } } } }")));
        AnalyzerRequestDto dto = new AnalyzerRequestDto();
        dto.setApiUrl("localhost:3665");
        dto.setCredentialKind(credDto);

        Assertions.assertNotNull(analyzerService.getAvailableProjects(dto));
    }

    @Test
    public void testReportList() {
        mockServer.stubFor(WireMock.post("/report").willReturn(WireMock.okJson("{ \"data\": { \"node\": { \"reports\": { \"edges\": [ { \"node\": { \"id\": \"UmVwb3J0OjU3MzE=\", \"name\": \"Report 1 for 211015_trace_all_lab01_opt.cst.gz\", \"__typename\": \"ReportDone\" } } ] } } } }")));
        AnalyzerRequestDto dto = new AnalyzerRequestDto();
        dto.setApiUrl("localhost:3665/report");
        dto.setCredentialKind(credDto);

        Assertions.assertNotNull(analyzerService.getAvailableReports(dto, "testProject"));
    }

    @Test
    public void testCertificateList() {
        mockServer.stubFor(WireMock.post("/certificate").willReturn(WireMock.okJson("{ \"data\": { \"node\": { \"certificates\": { \"edges\": [ { \"node\": { \"id\": \"Q2VydGlmaWNhdGU6MTYwNDc2\", \"serialNumber\": \"0\", \"subject\": \"E=sampo@iki.fi,CN=brutus.neuronio.pt,OU=Desenvolvimento,O=Neuronio\\\\, Lda.,L=Lisboa,ST=Queensland,C=PT\", \"issuer\": \"E=sampo@iki.fi,CN=brutus.neuronio.pt,OU=Desenvolvimento,O=Neuronio\\\\, Lda.,L=Lisboa,ST=Queensland,C=PT\", \"fingerprint\": \"2aa7e7002df6adf1c46c84f9f4149bdcaf3f3583\", \"encoded\": \"-----BEGIN CERTIFICATE-----\\nMIICLDCCAdYCAQAwDQYJKoZIhvcNAQEEBQAwgaAxCzAJBgNVBAYTAlBUMRMwEQYD\\nVQQIEwpRdWVlbnNsYW5kMQ8wDQYDVQQHEwZMaXNib2ExFzAVBgNVBAoTDk5ldXJv\\nbmlvLCBMZGEuMRgwFgYDVQQLEw9EZXNlbnZvbHZpbWVudG8xGzAZBgNVBAMTEmJy\\ndXR1cy5uZXVyb25pby5wdDEbMBkGCSqGSIb3DQEJARYMc2FtcG9AaWtpLmZpMB4X\\nDTk2MDkwNTAzNDI0M1oXDTk2MTAwNTAzNDI0M1owgaAxCzAJBgNVBAYTAlBUMRMw\\nEQYDVQQIEwpRdWVlbnNsYW5kMQ8wDQYDVQQHEwZMaXNib2ExFzAVBgNVBAoTDk5l\\ndXJvbmlvLCBMZGEuMRgwFgYDVQQLEw9EZXNlbnZvbHZpbWVudG8xGzAZBgNVBAMT\\nEmJydXR1cy5uZXVyb25pby5wdDEbMBkGCSqGSIb3DQEJARYMc2FtcG9AaWtpLmZp\\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAL7+aty3S1iBA/+yxjxv4q1MUTd1kjNw\\nL4lYKbpzzlmC5beaQXeQ2RmGMTXU+mDvuqItjVHOK3DvPK7lTcSGftUCAwEAATAN\\nBgkqhkiG9w0BAQQFAANBAFqPEKFjk6T6CKTHvaQeEAsX0/8YHPHqH/9AnhSjrwuX\\n9EBc0n6bVGhN7XaXd6sJ7dym9sbsWxb+pJdurnkxjx4=\\n-----END CERTIFICATE-----\" } }, { \"node\": { \"id\": \"Q2VydGlmaWNhdGU6MTYwNDc3\", \"serialNumber\": \"19\", \"subject\": \"CN=Y,OU=Testing,O=Testing,C=SE\", \"issuer\": \"CN=X,OU=Testing,O=Testing,C=SE\", \"fingerprint\": \"69d29b8cc2b8751c1bfb6a07f89edfcec6c01f04\", \"encoded\": \"-----BEGIN CERTIFICATE-----\\nMIIB6TCCAVICARkwDQYJKoZIhvcNAQEFBQAwPTELMAkGA1UEBhMCU0UxEDAOBgNV\\nBAoMB1Rlc3RpbmcxEDAOBgNVBAsMB1Rlc3RpbmcxCjAIBgNVBAMMAVgwHhcNMTIw\\nODA2MTI1NzQ2WhcNMjIwODA0MTI1NzQ2WjA9MQswCQYDVQQGEwJTRTEQMA4GA1UE\\nCgwHVGVzdGluZzEQMA4GA1UECwwHVGVzdGluZzEKMAgGA1UEAwwBWTCBnzANBgkq\\nhkiG9w0BAQEFAAOBjQAwgYkCgYEA3opXmKiRJm8UEd7MPdhkWQxoEvw5F50pTgmg\\nMWtAW9vYZ93pVcgDh5Ot39ohgEWVATItPo2NrBRNjwy3qZRx0i/4olj8632k/X43\\n0J0i6hPygXHgtWJc87yduc+OLgbyzVywMdVny+oGfYqO04wsiZto7xsMJNmCrtMj\\nW+6MPyUCAwEAATANBgkqhkiG9w0BAQUFAAOBgQBW4YijMw8TaWHL2NC4EI2mXeS1\\nDGg983YGV0rs328PmDwk72xmP77mYatQcDrA+WFxJulEdmJp+HymdKtRjp+ulcvi\\nSbXS9kXciV1Gk7EnamsrhZ6UxGWHbsAjPJunL+P9XRjQGA8bpOqiivilwQeMlXFn\\nmqrmGjorTts2bLrpLA==\\n-----END CERTIFICATE-----\" } } ] } } } }")));
        AnalyzerRequestDto dto = new AnalyzerRequestDto();
        dto.setApiUrl("localhost:3665/certificate");
        dto.setCredentialKind(credDto);

        Assertions.assertNotNull(analyzerService.listCertificates(dto, "testReport"));
    }

}
