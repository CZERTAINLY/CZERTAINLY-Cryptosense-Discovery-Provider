package org.czertainly.cryptosense.certificate.discovery.dto;

import com.czertainly.api.model.core.credential.CredentialDto;
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
    private CredentialDto credentialKind;
}
