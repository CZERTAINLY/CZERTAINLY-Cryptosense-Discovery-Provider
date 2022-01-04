create sequence IF NOT EXISTS cryptosense_discovery_certificate_id_seq start 1 increment 1;
create sequence IF NOT EXISTS cryptosense_discovery_id_seq start 1 increment 1;

ALTER TABLE cryptosense_discovery_certificate
	DROP COLUMN IF EXISTS "discovery_source";

ALTER TABLE cryptosense_discovery_certificate
	ADD IF NOT EXISTS "uuid" VARCHAR NULL;

ALTER TABLE cryptosense_discovery_history
    ADD IF NOT EXISTS "uuid" VARCHAR NULL;