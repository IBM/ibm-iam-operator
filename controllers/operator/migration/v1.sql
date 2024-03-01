-- Begin platformdb Schema

CREATE SCHEMA IF NOT EXISTS platformdb;

-- Begin Identity Provider Configuration

CREATE TABLE IF NOT EXISTS "platformdb"."idp_configs" (
    "uid" character varying NOT NULL,
    "description" character varying,
    "enabled" boolean DEFAULT true NOT NULL,
    "idp_config" jsonb,
    "name" character varying NOT NULL,
    "protocol" character varying(5) NOT NULL,
    "type" character varying,
    "scim_config" jsonb,
    "jit" boolean,
    "ldap_config" character varying,
    CONSTRAINT "idp_configs_uid" PRIMARY KEY ("uid")
) WITH (oids = false);

-- End Identity Provider Configuration

-- User Management

CREATE TABLE IF NOT EXISTS "platformdb"."users_preferences" (
    "user_id" character varying NOT NULL,
    "last_login" timestamptz NOT NULL,
    "last_logout" timestamptz,
    "login_count" int,
    CONSTRAINT "users_preferences_userid" PRIMARY KEY ("user_id")
) WITH (oids = false);


CREATE TABLE IF NOT EXISTS "platformdb"."users" (
    "uid" uuid DEFAULT gen_random_uuid() NOT NULL,
    "user_id" character varying NOT NULL,
    "realm_id" character varying,
    "first_name" character varying,
    "last_name" character varying,
    "email" character varying,
    "type" character varying,
    "last_login" timestamptz,
    "status" character varying,
    "user_basedn" character varying,
    "groups" text ARRAY,
    "role" character varying,
    "unique_security_name" character varying,
    "preferred_username" character varying,
    "display_name" character varying,
    "subject" character varying,
    CONSTRAINT "users_userid" PRIMARY KEY ("user_id"),
    CONSTRAINT "users_uid" UNIQUE ("uid")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "platformdb"."users_attributes" (
    "uid" uuid DEFAULT gen_random_uuid(),
    "user_uid" uuid NOT NULL,
    "name" character varying,
    "value" character varying,
    CONSTRAINT "users_attributes_uid" PRIMARY KEY ("uid"),
    CONSTRAINT "fk_useratt_fk" FOREIGN KEY ("user_uid") REFERENCES users ("uid")
) WITH (oids = false);

-- End User Management

-- Begin Zen Integration

CREATE TABLE IF NOT EXISTS "platformdb"."zen_instances" (
    "instance_id" character varying NOT NULL,
    "client_id" character varying NOT NULL,
    "client_secret" character varying NOT NULL,
    "product_name_url" character varying NOT NULL,
    "zen_audit_url" character varying,
    "namespace" character varying NOT NULL,
    CONSTRAINT "zen_instances_instance_id" PRIMARY KEY ("instance_id")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "platformdb"."zen_instances_users" (
    "uz_id" character varying NOT NULL,
    "zen_instance_id" character varying NOT NULL,
    "user_id" character varying NOT NULL,
    CONSTRAINT "zeninstances_users_uzid" PRIMARY KEY ("uz_id"),
    CONSTRAINT "fk_zenuser_fk" FOREIGN KEY ("zen_instance_id") REFERENCES zen_instances ("instance_id"),
    CONSTRAINT "fk_userzen_fk" FOREIGN KEY ("user_id") REFERENCES users ("user_id")
) WITH (oids = false);

-- End Zen Integration


-- Begin SCIM

CREATE TABLE IF NOT EXISTS "platformdb"."scim_attributes" (
    "id" character varying NOT NULL,
    "group" jsonb NOT NULL,
    "user" jsonb NOT NULL,
    CONSTRAINT "scim_attributes_id" UNIQUE ("id")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "platformdb"."scim_attributes_mappings" (
    "idp_id" character varying NOT NULL,
    "idp_type" character varying NOT NULL,
    "group" jsonb NOT NULL,
    "user" jsonb NOT NULL,
    CONSTRAINT "scim_attributemappings_idp_id" UNIQUE ("idp_id")
) WITH (oids = false);

-- End SCIM

-- Begin SCIM with JIT Flow

CREATE TABLE IF NOT EXISTS "platformdb"."groups" (
    "group_id" character varying NOT NULL,
    "display_name" character varying NOT NULL,
    "type" character varying NOT NULL,
    "realm_id" character varying NOT NULL,
    CONSTRAINT "groups_groupid" PRIMARY KEY ("group_id")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "platformdb"."members" (
    "member_id" character varying NOT NULL,
    "value" character varying,
    "display" character varying,
    CONSTRAINT "members_member_id" PRIMARY KEY ("member_id")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "platformdb"."groups_members" (
    "realm_id" character varying NOT NULL,
    "group_id" character varying NOT NULL,
    "member_id" character varying NOT NULL,
    CONSTRAINT "groupmembers_groupid_memberid,realm_id" PRIMARY KEY ("group_id,member_id,realm_id")
) WITH (oids = false);

-- End SCIM with JIT Flow

-- Begin SCIM Server Integration

CREATE TABLE IF NOT EXISTS platformdb.scim_server_users (
    id character varying(255) NOT NULL,
    schemas text[],
    "externalId" character varying(255),
    "userName" character varying(255),
    name json,
    "displayName" character varying(255),
    title character varying(255),
    "nickName" character varying(255),
    "profileUrl" character varying(255),
    emails json,
    addresses json,
    "phoneNumbers" json,
    ims json,
    photos json,
    "userType" character varying(255),
    "preferredLanguage" character varying(255),
    locale character varying(255),
    timezone character varying(255),
    "x509Certificates" json,
    active character varying(255),
    password character varying(255),
    meta json,
    groups json,
    "employeeNumber" character varying(255),
    "costCenter" character varying(255),
    organization character varying(255),
    division character varying(255),
    department character varying(255),
    manager json
);

ALTER TABLE platformdb.scim_server_users OWNER TO im_user;

CREATE TABLE IF NOT EXISTS platformdb.scim_server_users_custom (
    id character varying(255) NOT NULL,
    "userattributeKey" character varying(255) NOT NULL,
    "simpleValue" character varying(255),
    "complexValue" jsonb
);


ALTER TABLE platformdb.scim_server_users_custom OWNER TO im_user;

-- End SCIM Server Integration

-- End platformdb Schema

-- Begin oauthdbschema Schema

CREATE SCHEMA IF NOT EXISTS oauthdbschema;


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
  PROPS TEXT NOT NULL DEFAULT '{}',
  CONSTRAINT PK_LOOKUPKEY PRIMARY KEY ("LOOKUPKEY")
);

CREATE TABLE IF NOT EXISTS oauthdbschema.oauthclient
(
  _id SERIAL,
  CLIENTID VARCHAR(64) NOT NULL,
  PROVIDERID VARCHAR(256) NOT NULL,
  CLIENTSECRET VARCHAR(256),
  DISPLAYNAME VARCHAR(256) NOT NULL,
  ENABLED BOOLEAN,
  METADATA TEXT NOT NULL DEFAULT '{}',
  CONSTRAINT PK_COMPIDCLIENTID PRIMARY KEY (PROVIDERID,CLIENTID);
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

CREATE INDEX IF NOT EXISTS OAUTH20CACHE_EXPIRES ON oauthdbschema.oauthtoken (EXPIRES ASC);

-- End oauthdbschema Schema
