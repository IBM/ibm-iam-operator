-- Begin platformdb Schema

CREATE SCHEMA IF NOT EXISTS platformdb;

-- Begin Identity Provider Configuration

CREATE TABLE IF NOT EXISTS "platformdb"."idp_configs" (
    "uid" character varying NOT NULL,
    "description" character varying,
    "enabled" boolean DEFAULT 'true' NOT NULL,
    "idp_config" json,
    "name" character varying NOT NULL,
    "protocol" character varying(5) NOT NULL,
    "type" character varying,
    "scim_config" json,
    "jit" boolean,
    "ldap_config" json,
    CONSTRAINT "idp_configs_uid" PRIMARY KEY ("uid")
) WITH (oids = false);

-- End Identity Provider Configuration

-- User Management

CREATE TABLE IF NOT EXISTS "platformdb"."user_preferences" (
    "userid" character varying NOT NULL,
    "last_login" timestamptz NOT NULL,
    "last_logout" timestamptz,
    "login_count" int,
    CONSTRAINT "user_preferences_userid" PRIMARY KEY ("userid")
) WITH (oids = false);


CREATE TABLE IF NOT EXISTS "platformdb"."users" (
    "uid" character varying NOT NULL,
    "userid" character varying NOT NULL,
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
    CONSTRAINT "users_userid" PRIMARY KEY ("userid")
) WITH (oids = false);

CREATE INDEX IF NOT EXISTS userid_idx ON platformdb.users (userid);

CREATE TABLE IF NOT EXISTS "platformdb"."user_attributes" (
    "uid" character varying NOT NULL,
    "user_uid" character varying,
    "name" character varying,
    "value" character varying
) WITH (oids = false);

-- End User Management

-- Begin Zen Integration

CREATE TABLE IF NOT EXISTS "platformdb"."zeninstances" (
    "instanceid" character varying NOT NULL,
    "client_id" character varying NOT NULL,
    "client_secret" character varying NOT NULL,
    "product_name_url" character varying NOT NULL,
    "zen_audit_url" character varying,
    "namespace" character varying NOT NULL,
    CONSTRAINT "zeninstances_instanceId" PRIMARY KEY ("instanceid")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "platformdb"."zeninstanceusers" (
    "uzid" character varying NOT NULL,
    "zen_instanceid" character varying NOT NULL,
    "usersid" character varying NOT NULL,
    CONSTRAINT "zeninstanceusers_uzid" PRIMARY KEY ("uzid")
) WITH (oids = false);

-- End Zen Integration


-- Begin SCIM

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

-- End SCIM

-- Begin SCIM with JIT Flow

CREATE TABLE IF NOT EXISTS "platformdb"."groups" (
    "groupid" character varying NOT NULL,
    "display_name" character varying NOT NULL,
    "type" character varying NOT NULL,
    "realm_id" character varying NOT NULL,
    CONSTRAINT "groups_groupid" PRIMARY KEY ("groupid")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "platformdb"."members" (
    "memberid" character varying NOT NULL,
    "value" character varying,
    "display" character varying,
    CONSTRAINT "members_memberid" PRIMARY KEY ("memberid")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "platformdb"."groupmembers" (
    "realm_id" character varying NOT NULL,
    "groupid" character varying NOT NULL,
    "memberid" character varying NOT NULL,
    CONSTRAINT "groupmembers_groupid_memberid_realm_id"
    PRIMARY KEY ("groupid", "memberid", "realm_id")
) WITH (oids = false);

-- End SCIM with JIT Flow

-- Begin SCIM Server Integration

CREATE TABLE IF NOT EXISTS platformdb.scim_server_users (
    id character varying(255) NOT NULL,
    schemas text [],
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
    "complexValue" json
);


ALTER TABLE platformdb.scim_server_users_custom OWNER TO im_user;

-- End SCIM Server Integration

-- End platformdb Schema

-- Begin oauthdbschema Schema

CREATE SCHEMA IF NOT EXISTS oauthdbschema;

CREATE TABLE IF NOT EXISTS oauthdbschema.oauthtoken
(
    _id serial,
    lookupkey varchar(256) NOT NULL,
    uniqueid varchar(2048) NOT NULL,
    providerid varchar(256) NOT NULL,
    type varchar(64) NOT NULL,
    subtype varchar(64),
    createdat bigint,
    lifetime int,
    expires bigint,
    tokenstring varchar(32768) NOT NULL,
    clientid varchar(64) NOT NULL,
    username varchar(64) NOT NULL,
    scope varchar(512) NOT NULL,
    redirecturi varchar(2048),
    stateid varchar(64) NOT NULL,
    props text NOT NULL DEFAULT '{}',
    CONSTRAINT pk_lookupkey PRIMARY KEY (lookupkey)
);

CREATE TABLE IF NOT EXISTS oauthdbschema.oauthclient
(
    _id serial,
    clientid varchar(64) NOT NULL,
    providerid varchar(256) NOT NULL,
    clientsecret varchar(256),
    displayname varchar(256) NOT NULL,
    enabled boolean,
    metadata text NOT NULL DEFAULT '{}',
    CONSTRAINT pk_compidclientid PRIMARY KEY (providerid, clientid)
);

CREATE TABLE IF NOT EXISTS oauthdbschema.oauthconsent
(
    _id serial,
    clientid varchar(64) NOT NULL,
    username varchar(64) NOT NULL,
    scope varchar(512) NOT NULL,
    resource varchar(512),
    providerid varchar(256) NOT NULL,
    expires bigint,
    props text NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS oauth20cache_expires
ON oauthdbschema.oauthtoken (expires ASC);

-- End oauthdbschema Schema
