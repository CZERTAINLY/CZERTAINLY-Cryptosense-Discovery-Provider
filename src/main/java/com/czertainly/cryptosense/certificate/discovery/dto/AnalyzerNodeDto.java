package com.czertainly.cryptosense.certificate.discovery.dto;

import lombok.Getter;

@Getter
public class AnalyzerNodeDto {
    private String id;
    private String name;
    private String api;
    private AnalyzerReportsDto reports;
    private AnalyzerCertificatesDto certificates;
    private String __typename;

    private String serialNumber;
    private String subject;
    private String issuer;
    private String fingerprint;
    private String encoded;
}
