--
-- Copyright 2024 IBM Corporation
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Begin platformdb Schema

CREATE SCHEMA IF NOT EXISTS platformdb;

-- Begin Identity Provider Configuration

CREATE TABLE IF NOT EXISTS "platformdb"."idp_configs" (
    "uid" character varying NOT NULL,
    "description" character varying,
    "enabled" boolean DEFAULT true NOT NULL,
    "idp_config" jsonb,
    "name" character varying NOT NULL,
    "protocol" character varying(10) NOT NULL,
    "type" character varying,
    "scim_config" jsonb,
    "jit" boolean,
    "ldap_id" character varying,
    CONSTRAINT "idp_configs_uid" PRIMARY KEY ("uid")
) WITH (oids = false);

-- End Identity Provider Configuration

-- User Management

CREATE TABLE IF NOT EXISTS "platformdb"."users" (
    "uid" uuid DEFAULT gen_random_uuid() NOT NULL,
    "user_id" character varying NOT NULL,
    "realm_id" character varying,
    "first_name" character varying,
    "last_name" character varying,
    "email" character varying,
    "type" character varying,
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

CREATE TABLE IF NOT EXISTS "platformdb"."users_preferences" (
    "uid" uuid DEFAULT gen_random_uuid() NOT NULL,
    "user_uid" uuid NOT NULL,
    "last_login" timestamptz NOT NULL,
    "last_logout" timestamptz,
    "login_count" int,
    CONSTRAINT "users_preferences_uid" PRIMARY KEY ("uid"),
    CONSTRAINT "users_preferences_useruid" UNIQUE ("user_uid"),
    CONSTRAINT "fk_userpref_fk"
    FOREIGN KEY ("user_uid")
    REFERENCES "platformdb"."users" ("uid")
    ON DELETE CASCADE
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "platformdb"."users_attributes" (
    "uid" uuid DEFAULT gen_random_uuid(),
    "user_uid" uuid NOT NULL,
    "name" character varying,
    "value" character varying,
    CONSTRAINT "users_attributes_uid" PRIMARY KEY ("uid"),
    CONSTRAINT "fk_useratt_fk"
    FOREIGN KEY ("user_uid")
    REFERENCES "platformdb"."users" ("uid")
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
    "uid" uuid DEFAULT gen_random_uuid(),
    "zen_instance_id" character varying NOT NULL,
    "user_id" character varying NOT NULL,
    CONSTRAINT "zeninstances_users_uid" PRIMARY KEY ("uid"),
    CONSTRAINT "fk_zenuser_fk" FOREIGN KEY ("zen_instance_id")
    REFERENCES "platformdb"."zen_instances" ("instance_id"),
    CONSTRAINT "fk_userzen_fk" FOREIGN KEY ("user_id")
    REFERENCES "platformdb"."users" ("user_id")
) WITH (oids = false);
-- End Zen Integration


-- Begin SCIM

CREATE TABLE IF NOT EXISTS "platformdb"."scim_attributes" (
    "id" character varying NOT NULL,
    "group" jsonb,
    "user" jsonb,
    CONSTRAINT "scim_attributes_id" UNIQUE ("id")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "platformdb"."scim_attributes_mappings" (
    "idp_id" character varying NOT NULL,
    "idp_type" character varying NOT NULL,
    "group" jsonb,
    "user" jsonb,
    CONSTRAINT "scim_attributemappings_idp_id" UNIQUE ("idp_id")
) WITH (oids = false);
-- End SCIM

-- Begin SCIM with JIT Flow

CREATE TABLE IF NOT EXISTS "platformdb"."groups" (
    "uid" uuid DEFAULT gen_random_uuid() NOT NULL,
    "group_id" character varying NOT NULL,
    "display_name" character varying NOT NULL,
    "realm_id" character varying NOT NULL,
    CONSTRAINT "groups_group_id_realm_id" UNIQUE ("group_id", "realm_id"),
    CONSTRAINT "groups_pkey" PRIMARY KEY ("uid")
) WITH (oids = false);

CREATE TABLE IF NOT EXISTS "platformdb"."users_groups" (
    "user_uid" uuid NOT NULL,
    "group_uid" uuid NOT NULL,
    CONSTRAINT "users_groups_pkey" PRIMARY KEY ("user_uid", "group_uid")
) WITH (oids = false);

ALTER TABLE ONLY "platformdb"."users_groups"
ADD CONSTRAINT "users_groups_group_uid_fkey"
FOREIGN KEY (group_uid) REFERENCES "platformdb"."groups" (uid) ON DELETE CASCADE;
ALTER TABLE ONLY "platformdb"."users_groups"
ADD CONSTRAINT "users_groups_user_uid_fkey"
FOREIGN KEY (user_uid) REFERENCES "platformdb"."users" (uid) ON DELETE CASCADE;

-- End SCIM with JIT Flow

-- Begin SCIM Server Integration

CREATE TABLE "platformdb"."scim_server_users" (
    id character varying(255) NOT NULL,
    schemas text [],
    external_id character varying(255),
    user_name character varying(255),
    name jsonb,
    display_name character varying(255),
    emails jsonb,
    addresses jsonb,
    phone_numbers jsonb,
    user_type character varying(255),
    active boolean,
    meta jsonb,
    groups jsonb
) WITH (oids = false);

ALTER TABLE ONLY platformdb.scim_server_users
ADD CONSTRAINT scim_server_users_pkey PRIMARY KEY (id);

CREATE TABLE platformdb.scim_server_users_custom (
    scim_server_user_uid character varying(255) NOT NULL,
    attribute_key character varying(255) NOT NULL,
    schema_name character varying(255),
    attribute_value character varying,
    attribute_value_complex jsonb
) WITH (oids = false);

ALTER TABLE ONLY platformdb.scim_server_users_custom
ADD CONSTRAINT scim_server_users_custom_pkey
PRIMARY KEY (scim_server_user_uid, attribute_key);

ALTER TABLE ONLY platformdb.scim_server_users_custom
ADD CONSTRAINT scim_server_users_custom_scim_server_user_uid_fkey
FOREIGN KEY (scim_server_user_uid)
REFERENCES "platformdb"."scim_server_users" (id)
ON UPDATE CASCADE
ON DELETE CASCADE;

CREATE TABLE "platformdb"."scim_server_groups" (
    id character varying(255) NOT NULL,
    schemas text [],
    members jsonb,
    display_name character varying(255),
    meta jsonb
) WITH (oids = false);

ALTER TABLE ONLY platformdb.scim_server_groups
ADD CONSTRAINT scim_server_groups_pkey
PRIMARY KEY (id);


CREATE TABLE platformdb.scim_server_groups_custom (
    scim_server_group_uid character varying(255) NOT NULL,
    attribute_key character varying(255) NOT NULL,
    schema_name character varying(255),
    attribute_value character varying,
    attribute_value_complex jsonb
) WITH (oids = false);

ALTER TABLE ONLY platformdb.scim_server_groups_custom
ADD CONSTRAINT scim_server_groups_custom_pkey
PRIMARY KEY (scim_server_group_uid, attribute_key);

ALTER TABLE ONLY platformdb.scim_server_groups_custom
ADD CONSTRAINT scim_server_groups_custom_scim_server_group_uid_fkey
FOREIGN KEY (scim_server_group_uid)
REFERENCES platformdb.scim_server_groups (id)
ON UPDATE CASCADE
ON DELETE CASCADE;

CREATE VIEW
platformdb.view_scim_server_users_custom AS SELECT
    scim_server_user_uid,
    jsonb_object_agg(attribute_key, attribute_value) AS col_value,
    jsonb_object_agg(attribute_key, attribute_value_complex) AS col_complex
FROM platformdb.scim_server_users_custom
GROUP BY (scim_server_user_uid);
CREATE VIEW platformdb.view_scim_server_groups_custom AS SELECT
    scim_server_group_uid,
    jsonb_object_agg(attribute_key, attribute_value) AS col_value,
    jsonb_object_agg(attribute_key, attribute_value_complex) AS col_complex
FROM platformdb.scim_server_groups_custom
GROUP BY (scim_server_group_uid);

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
