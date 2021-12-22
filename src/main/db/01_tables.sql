create sequence cryptosense_discovery_certificate_id_seq start 1 increment 1;
create sequence cryptosense_discovery_id_seq start 1 increment 1;

CREATE TABLE "cryptosense_discovery_certificate" (
	"id" BIGINT NOT NULL,
	"uuid" VARCHAR NOT NULL DEFAULT NULL,
	"base64content" VARCHAR NULL DEFAULT NULL,
	"discovery_id" BIGINT NULL DEFAULT NULL,
	"i_author" VARCHAR NULL DEFAULT NULL,
	"i_cre" DATE NULL DEFAULT NULL,
	"i_upd" DATE NULL DEFAULT NULL,
    "meta" TEXT NULL DEFAULT NULL,
	PRIMARY KEY ("id")
)
;

CREATE TABLE "cryptosense_discovery_history" (
	"id" BIGINT NOT NULL,
	"uuid" VARCHAR NOT NULL,
	"name" VARCHAR NOT NULL,
	"status" VARCHAR NOT NULL,
	"i_author" VARCHAR NULL DEFAULT NULL,
	"i_cre" DATE NULL DEFAULT NULL,
	"i_upd" DATE NULL DEFAULT NULL,
	"meta" TEXT NULL DEFAULT NULL,
	PRIMARY KEY ("id")
)
;

