/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License").
 *  You may not use this file except in compliance with the License.
 *  A copy of the License is located at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  or in the "license" file accompanying this file. This file is distributed
 *  on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *  express or implied. See the License for the specific language governing
 *  permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.dlic.rest.api;

import java.io.IOException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.elasticsearch.client.Client;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.collect.Tuple;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.rest.RestController;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.rest.RestRequest.Method;
import org.elasticsearch.rest.RestResponse;
import org.elasticsearch.threadpool.ThreadPool;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.amazon.opendistroforelasticsearch.security.auditlog.AuditLog;
import com.amazon.opendistroforelasticsearch.security.configuration.AdminDNs;
import com.amazon.opendistroforelasticsearch.security.configuration.IndexBaseConfigurationRepository;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.support.Utils;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.AbstractConfigurationValidator;
import com.amazon.opendistroforelasticsearch.security.dlic.rest.validation.InternalUsersValidator;
import com.amazon.opendistroforelasticsearch.security.privileges.PrivilegesEvaluator;
import com.amazon.opendistroforelasticsearch.security.ssl.transport.PrincipalExtractor;
import com.amazon.opendistroforelasticsearch.security.support.ConfigConstants;

public class InternalUsersApiAction extends PatchableResourceApiAction {

    @Inject
    public InternalUsersApiAction(final Settings settings, final Path configPath, final RestController controller,
            final Client client, final AdminDNs adminDNs, final IndexBaseConfigurationRepository cl,
            final ClusterService cs, final PrincipalExtractor principalExtractor, final PrivilegesEvaluator evaluator,
            ThreadPool threadPool, AuditLog auditLog) {
        super(settings, configPath, controller, client, adminDNs, cl, cs, principalExtractor, evaluator, threadPool,
                auditLog);

        // legacy mapping for backwards compatibility
        // TODO: remove in next version
        controller.registerHandler(Method.GET, "/_opendistro/_security/api/user/{name}", this);
        controller.registerHandler(Method.GET, "/_opendistro/_security/api/user/", this);
        controller.registerHandler(Method.DELETE, "/_opendistro/_security/api/user/{name}", this);
        controller.registerHandler(Method.PUT, "/_opendistro/_security/api/user/{name}", this);

        // corrected mapping, introduced in Open Distro Security
        controller.registerHandler(Method.GET, "/_opendistro/_security/api/internalusers/{name}", this);
        controller.registerHandler(Method.GET, "/_opendistro/_security/api/internalusers/", this);
        controller.registerHandler(Method.DELETE, "/_opendistro/_security/api/internalusers/{name}", this);
        controller.registerHandler(Method.PUT, "/_opendistro/_security/api/internalusers/{name}", this);
        controller.registerHandler(Method.PATCH, "/_opendistro/_security/api/internalusers/", this);
        controller.registerHandler(Method.PATCH, "/_opendistro/_security/api/internalusers/{name}", this);

    }

    @Override
    protected Endpoint getEndpoint() {
        return Endpoint.INTERNALUSERS;
    }

    @Override
    protected Tuple<String[], RestResponse> handlePut(final RestRequest request, final Client client,
            final Settings.Builder additionalSettingsBuilder) throws Throwable {

        final String username = request.param("name");

        if (username == null || username.length() == 0) {
            return badRequestResponse("No " + getResourceName() + " specified");
        }

        if(username.contains(".")) {
            return badRequestResponse("No dots are allowed in the name. User the username attribute.");
        }

        // TODO it might be sensible to consolidate this with the overridden method in
        // order to minimize duplicated logic

        final Settings configurationSettings = loadAsSettings(getConfigName(), false);

        if (isHidden(configurationSettings, username)) {
            return forbidden("Resource '" + username + "' is not available.");
        }

        // check if resource is writeable
        Boolean readOnly = configurationSettings.getAsBoolean(username + "." + ConfigConstants.CONFIGKEY_READONLY,
                Boolean.FALSE);
        if (readOnly) {
            return forbidden("Resource '" + username + "' is read-only.");
        }

        // if password is set, it takes precedence over hash
        String plainTextPassword = additionalSettingsBuilder.get("password");
        if (plainTextPassword != null && plainTextPassword.length() > 0) {
            additionalSettingsBuilder.remove("password");
            additionalSettingsBuilder.put("hash", hash(plainTextPassword.toCharArray()));
        }

        // check if user exists
        final Settings.Builder internaluser = load(ConfigConstants.CONFIGNAME_INTERNAL_USERS, false);
        final Map<String, Object> config = Utils.convertJsonToxToStructuredMap(internaluser.build());

        final boolean userExisted = config.containsKey(username);

        // when updating an existing user password hash can be blank, which means no
        // changes

        // sanity checks, hash is mandatory for newly created users
        if (!userExisted && additionalSettingsBuilder.get("hash") == null) {
            return badRequestResponse("Please specify either 'hash' or 'password' when creating a new internal user");
        }

        // for existing users, hash is optional
        if (userExisted && additionalSettingsBuilder.get("hash") == null) {
            // sanity check, this should usually not happen
            @SuppressWarnings("unchecked")
            Map<String, String> existingUserSettings = (Map<String, String>) config.get(username);
            if (!existingUserSettings.containsKey("hash")) {
                return internalErrorResponse(
                        "Existing user " + username + " has no password, and no new password or hash was specified");
            }
            additionalSettingsBuilder.put("hash", (String) existingUserSettings.get("hash"));
        }

        config.remove(username);

        // checks complete, create or update the user
        config.put(username, Utils.convertJsonToxToStructuredMap(additionalSettingsBuilder.build()));

        save(client, request, ConfigConstants.CONFIGNAME_INTERNAL_USERS, Utils.convertStructuredMapToBytes(config));

        if (userExisted) {
            return successResponse("'" + username + "' updated", ConfigConstants.CONFIGNAME_INTERNAL_USERS);
        } else {
            return createdResponse("'" + username + "' created", ConfigConstants.CONFIGNAME_INTERNAL_USERS);
        }

    }

    @Override
    protected void filter(Settings.Builder builder) {
        super.filter(builder);
        // replace password hashes in addition. We must not remove them from the
        // Builder since this would remove users completely if they
        // do not have any addition properties like roles or attributes
        Set<String> entries = builder.build().getAsGroups().keySet();
        for (String key : entries) {
            builder.put(key + ".hash", "");
        }
    }

    @Override
    protected AbstractConfigurationValidator postProcessApplyPatchResult(RestRequest request, JsonNode existingResourceAsJsonNode,
            JsonNode updatedResourceAsJsonNode, String resourceName) {
    	AbstractConfigurationValidator retVal = null;
        JsonNode passwordNode = updatedResourceAsJsonNode.get("password");

        if (passwordNode != null) {
            String plainTextPassword = passwordNode.asText();
            try {
				XContentBuilder builder = XContentBuilder.builder(JsonXContent.jsonXContent);
				builder.startObject();
				builder.field("password", plainTextPassword);
				builder.endObject();
				retVal = getValidator(request, BytesReference.bytes(builder), resourceName);
			} catch (IOException e) {
				log.error(e);
			}

            ((ObjectNode) updatedResourceAsJsonNode).remove("password");
            ((ObjectNode) updatedResourceAsJsonNode).set("hash", new TextNode(hash(plainTextPassword.toCharArray())));
            return retVal;
        }

        return null;
    }

    public static String hash(final char[] clearTextPassword) {
        final byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        final String hash = OpenBSDBCrypt.generate((Objects.requireNonNull(clearTextPassword)), salt, 12);
        Arrays.fill(salt, (byte) 0);
        Arrays.fill(clearTextPassword, '\0');
        return hash;
    }

    @Override
    protected String getResourceName() {
        return "user";
    }

    @Override
    protected String getConfigName() {
        return ConfigConstants.CONFIGNAME_INTERNAL_USERS;
    }

    @Override
    protected AbstractConfigurationValidator getValidator(RestRequest request, BytesReference ref, Object... params) {
        return new InternalUsersValidator(request, ref, this.settings, params);
    }
}
