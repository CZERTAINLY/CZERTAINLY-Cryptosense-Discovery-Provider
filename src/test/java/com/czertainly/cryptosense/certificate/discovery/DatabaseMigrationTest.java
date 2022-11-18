package com.czertainly.cryptosense.certificate.discovery;

import com.czertainly.core.util.DatabaseMigrationUtils;
import com.czertainly.cryptosense.certificate.discovery.enums.JavaMigrationChecksums;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * Simple tests for calculating checksums and validating the migration scripts integrity.
 */
public class DatabaseMigrationTest {

    @Test
    public void testCalculateChecksum_V202211111930__MetadataToInfoAttributeMigration() {
        int checksum = DatabaseMigrationUtils.calculateChecksum("src/main/java/db/migration/V202211111930__MetadataToInfoAttributeMigration.java");

        Assertions.assertEquals(JavaMigrationChecksums.V202211111930__MetadataToInfoAttributeMigration.getChecksum(), checksum);
    }
}
