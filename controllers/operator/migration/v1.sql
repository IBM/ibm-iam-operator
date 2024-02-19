CREATE SCHEMA IF NOT EXISTS platformdb;
CREATE SCHEMA IF NOT EXISTS oauthdbschema;
CREATE SCHEMA IF NOT EXISTS public;


CREATE TABLE IF NOT EXISTS "platformdb"."idp_configs" (
    "uid" character varying NOT NULL,
    "description" character varying,
    "enabled" character varying(5) DEFAULT 'true' NOT NULL,
    "idp_config" json,
    "name" character varying NOT NULL,
    "protocol" character varying(5) NOT NULL,
    "type" character varying,
    "scim_config" json,
    "jit" boolean,
    "ldap_config" json,
    CONSTRAINT "idp_config_uid" PRIMARY KEY (uid)
) WITH (oids = false);


CREATE TABLE IF NOT EXISTS "platformdb"."user_preferences" (
    "userId" character varying NOT NULL,
    "lastLogin" timestamptz NOT NULL,
    "lastLogout" timestamptz,
    "loginCount" int,
    CONSTRAINT "user_preferences_userId" PRIMARY KEY ("userId")
) WITH (oids = false);


CREATE TABLE IF NOT EXISTS "platformdb"."users" (
    "userId" character varying NOT NULL,
    "directoryId" character varying,
    "firstName" character varying,
    "lastName" character varying,
    "email" character varying,
    "type" character varying,
    "lastLogin" timestamptz,
    "status" character varying,
    "userBaseDN" character varying,
    "userGroupId" text ARRAY,
    "role" character varying,
    "uniqueSecurityName" character varying,
    "preferred_username" character varying,
    "displayName" character varying,
    "subject" character varying,
    CONSTRAINT "users_userId" PRIMARY KEY ("userId")
) WITH (oids = false);


CREATE TABLE IF NOT EXISTS "platformdb"."zeninstances" (
    "instanceId" character varying NOT NULL,
    "clientId" character varying NOT NULL,
    "clientSecret" character varying NOT NULL,
    "productNameUrl" character varying NOT NULL,
    "zenAuditUrl" character varying NOT NULL,
    "namespace" character varying NOT NULL,
    CONSTRAINT "zeninstances_instanceId" PRIMARY KEY ("instanceId")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "public"."zeninstanceusers" (
    "UZId" character varying NOT NULL,
    "zenInstanceId" character varying NOT NULL,
    "usersId" character varying NOT NULL,
    CONSTRAINT "zeninstanceusers_UZId" PRIMARY KEY ("UZId")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "platformdb"."scim_attributes" (
    "id" character varying NOT NULL,
    "group" json NOT NULL,
    "user" json NOT NULL,
    CONSTRAINT "scim_attributes_id" UNIQUE ("id")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "platformdb"."scim_attributemappings" (
    "idp_id" character varying NOT NULL,
    "idp_type" character varying NOT NULL,
    "group" json NOT NULL,
    "user" json NOT NULL,
    CONSTRAINT "scim_attributemappings_id" UNIQUE ("idp_id")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "public"."scim_server_user_names" (
    "uid" integer NOT NULL,
    "formatted" integer NOT NULL,
    "family_name" integer NOT NULL,
    "given_name" integer,
    "middle_name" integer,
    "honorific_prefix" integer NOT NULL,
    "honorific_suffix" integer,
    "user_uid" integer
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "public"."scim_server_users" (
    "uid" character varying NOT NULL,
    "user_name" character varying,
    "display_name" character varying,
    "userid" character varying,
    "external_id" character varying,
    "meta" json
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS oauthdbschema.oauthtoken
(
  _id SERIAL,
  LOOKUPKEY VARCHAR(256) NOT NULL,
  UNIQUEID VARCHAR(2048) NOT NULL,
  PROVIDERID VARCHAR(256) NOT NULL,
  TYPE VARCHAR(64) NOT NULL,
  SUBTYPE VARCHAR(64),
  CREATEDAT BIGINT,
  LIFETIME INT,
  EXPIRES BIGINT,
  TOKENSTRING VARCHAR(32768) NOT NULL,
  CLIENTID VARCHAR(64) NOT NULL,
  USERNAME VARCHAR(64) NOT NULL,
  SCOPE VARCHAR(512) NOT NULL,
  REDIRECTURI VARCHAR(2048),
  STATEID VARCHAR(64) NOT NULL,
  PROPS TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS oauthdbschema.oauthclient
(
  _id SERIAL,
  CLIENTID VARCHAR(64) NOT NULL,
  PROVIDERID VARCHAR(256) NOT NULL,
  CLIENTSECRET VARCHAR(256),
  DISPLAYNAME VARCHAR(256) NOT NULL,
  ENABLED BOOLEAN,
  METADATA TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS oauthdbschema.oauthconsent
(
  _id SERIAL,
  CLIENTID VARCHAR(64) NOT NULL,
  USERNAME VARCHAR(64) NOT NULL,
  SCOPE VARCHAR(512) NOT NULL,
  RESOURCE VARCHAR(512), 
  PROVIDERID VARCHAR(256) NOT NULL,
  EXPIRES BIGINT,
  PROPS TEXT NOT NULL DEFAULT '{}'
);

ALTER TABLE oauthdbschema.oauthtoken DROP CONSTRAINT IF EXISTS pk_lookupkey,
  ADD CONSTRAINT pk_lookupkey PRIMARY KEY (lookupkey);

ALTER TABLE oauthdbschema.oauthclient DROP CONSTRAINT IF EXISTS pk_compidclientid,
  ADD CONSTRAINT pk_compidclientid PRIMARY KEY (providerid,clientid);

CREATE INDEX IF NOT EXISTS OAUTH20CACHE_EXPIRES ON oauthdbschema.oauthtoken (EXPIRES ASC);
