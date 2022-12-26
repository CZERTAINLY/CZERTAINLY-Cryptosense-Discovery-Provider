package com.czertainly.cryptosense.certificate.discovery.dto;

import com.czertainly.api.model.common.attribute.v2.content.data.CredentialAttributeContentData;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class AnalyzerRequestDto {

    private String apiUrl;
    private CredentialAttributeContentData credentialKind;
}
