package com.czertainly.cryptosense.certificate.discovery.cryptosense;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AnalyzerCertificate {

    private String id;
    private String serialNumber;
    private String subject;
    private String issuer;
    private String fingerprint;
    private String encoded;

}
