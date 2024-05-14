/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.entitlement.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.entitlement.EntitlementException;
import org.wso2.carbon.identity.entitlement.common.EntitlementConstants;
import org.wso2.carbon.identity.entitlement.dto.PublisherDataHolder;
import org.wso2.carbon.identity.entitlement.dto.PublisherPropertyDTO;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.wso2.carbon.identity.entitlement.PDPConstants.EntitlementTableColumns;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.CREATE_SUBSCRIBER_PROPERTIES_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.CREATE_SUBSCRIBER_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.DELETE_SUBSCRIBER_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_SUBSCRIBER_EXISTENCE_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_SUBSCRIBER_IDS_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.GET_SUBSCRIBER_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.UPDATE_SUBSCRIBER_MODULE_SQL;
import static org.wso2.carbon.identity.entitlement.dao.SQLQueries.UPDATE_SUBSCRIBER_PROPERTIES_SQL;

/**
 * This is for subscriber management
 */
public class SubscriberManager implements SubscriberManagerModule {

    public static final String SUBSCRIBER_ID = "subscriberId";
    private static final Log log = LogFactory.getLog(SubscriberManager.class);


    /**
     * Creates a subscriber manager
     */
    public SubscriberManager() {
    }


    /**
     * Adds a subscriber
     *
     * @param holder publisher data holder
     * @param update whether the operation indicates update or create
     * @throws EntitlementException throws, if fails
     */
    @Override
    public void persistSubscriber(PublisherDataHolder holder, boolean update) throws EntitlementException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String subscriberId = null;

        if (holder == null || holder.getPropertyDTOs() == null) {
            log.error("Publisher data can not be null");
            throw new EntitlementException("Publisher data can not be null");
        }

        for (PublisherPropertyDTO dto : holder.getPropertyDTOs()) {
            if (SUBSCRIBER_ID.equals(dto.getId())) {
                subscriberId = dto.getValue();
            }
        }

        if (subscriberId == null) {
            log.error("Subscriber Id can not be null");
            throw new EntitlementException("Subscriber Id can not be null");
        }

        try {

            PublisherDataHolder oldHolder = null;

            //Find whether the subscriber already exists
            PreparedStatement findSubscriberExistencePrepStmt =
                    connection.prepareStatement(GET_SUBSCRIBER_EXISTENCE_SQL);
            findSubscriberExistencePrepStmt.setString(1, subscriberId);
            findSubscriberExistencePrepStmt.setInt(2, tenantId);
            ResultSet rs1 = findSubscriberExistencePrepStmt.executeQuery();

            if (rs1.next()) {
                if (update) {
                    //Get the existing subscriber
                    PreparedStatement getSubscriberPrepStmt = connection.prepareStatement(GET_SUBSCRIBER_SQL);
                    getSubscriberPrepStmt.setString(1, subscriberId);
                    getSubscriberPrepStmt.setInt(2, tenantId);
                    ResultSet rs2 = getSubscriberPrepStmt.executeQuery();

                    if (rs2.next()) {
                        oldHolder = new PublisherDataHolder(rs2, false);
                    }

                    IdentityDatabaseUtil.closeResultSet(rs2);
                    IdentityDatabaseUtil.closeStatement(getSubscriberPrepStmt);

                } else {
                    throw new EntitlementException("Subscriber ID already exists");
                }
            }

            IdentityDatabaseUtil.closeResultSet(rs1);
            IdentityDatabaseUtil.closeStatement(findSubscriberExistencePrepStmt);

            populateProperties(holder, oldHolder);
            PublisherPropertyDTO[] propertyDTOs = holder.getPropertyDTOs();

            //Create a new subscriber
            if (!update) {
                PreparedStatement createSubscriberPrepStmt = connection.prepareStatement(CREATE_SUBSCRIBER_SQL);
                createSubscriberPrepStmt.setString(1, subscriberId);
                createSubscriberPrepStmt.setInt(2, tenantId);
                createSubscriberPrepStmt.setString(3, holder.getModuleName());
                createSubscriberPrepStmt.executeUpdate();
                IdentityDatabaseUtil.closeStatement(createSubscriberPrepStmt);

                PreparedStatement createSubscriberPropertiesPrepStmt =
                        connection.prepareStatement(CREATE_SUBSCRIBER_PROPERTIES_SQL);

                for (PublisherPropertyDTO dto : propertyDTOs) {
                    if (dto.getId() != null && dto.getValue() != null && !dto.getValue().trim().isEmpty()) {

                        int isRequired = (dto.isRequired()) ? 1 : 0;
                        int isSecret = (dto.isSecret()) ? 1 : 0;

                        createSubscriberPropertiesPrepStmt.setString(1, dto.getId());
                        createSubscriberPropertiesPrepStmt.setString(2, dto.getDisplayName());
                        createSubscriberPropertiesPrepStmt.setString(3, dto.getValue());
                        createSubscriberPropertiesPrepStmt.setInt(4, isRequired);
                        createSubscriberPropertiesPrepStmt.setInt(5, dto.getDisplayOrder());
                        createSubscriberPropertiesPrepStmt.setInt(6, isSecret);
                        createSubscriberPropertiesPrepStmt.setString(7, dto.getModule());
                        createSubscriberPropertiesPrepStmt.setString(8, subscriberId);
                        createSubscriberPropertiesPrepStmt.setInt(9, tenantId);

                        createSubscriberPropertiesPrepStmt.addBatch();
                    }
                }

                createSubscriberPropertiesPrepStmt.executeBatch();
                IdentityDatabaseUtil.closeStatement(createSubscriberPropertiesPrepStmt);

            } else {

                //Update the module of an existing subscriber
                assert oldHolder != null;
                if (!oldHolder.getModuleName().equalsIgnoreCase(holder.getModuleName())) {
                    PreparedStatement updateSubscriberPrepStmt =
                            connection.prepareStatement(UPDATE_SUBSCRIBER_MODULE_SQL);
                    updateSubscriberPrepStmt.setString(1, holder.getModuleName());
                    updateSubscriberPrepStmt.setString(2, subscriberId);
                    updateSubscriberPrepStmt.setInt(3, tenantId);
                    updateSubscriberPrepStmt.executeUpdate();
                    IdentityDatabaseUtil.closeStatement(updateSubscriberPrepStmt);
                }

                //Update the property values of an existing subscriber
                PreparedStatement updateSubscriberPropertiesPrepStmt =
                        connection.prepareStatement(UPDATE_SUBSCRIBER_PROPERTIES_SQL);

                for (PublisherPropertyDTO dto : propertyDTOs) {
                    if (dto.getId() != null && dto.getValue() != null && !dto.getValue().trim().isEmpty()) {

                        PublisherPropertyDTO propertyDTO;
                        propertyDTO = oldHolder.getPropertyDTO(dto.getId());
                        if (propertyDTO != null && !propertyDTO.getValue().equalsIgnoreCase(dto.getValue())) {
                            updateSubscriberPropertiesPrepStmt.setString(1, dto.getValue());
                            updateSubscriberPropertiesPrepStmt.setString(2, subscriberId);
                            updateSubscriberPropertiesPrepStmt.setInt(3, tenantId);
                            updateSubscriberPropertiesPrepStmt.setString(4, dto.getId());
                            updateSubscriberPropertiesPrepStmt.addBatch();
                        }
                    }
                }
                updateSubscriberPropertiesPrepStmt.executeBatch();
                IdentityDatabaseUtil.closeStatement(updateSubscriberPropertiesPrepStmt);
            }

            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            log.error("Error while persisting subscriber details", e);
            throw new EntitlementException("Error while persisting subscriber details", e);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }


    /**
     * Deletes a subscriber
     *
     * @param subscriberId subscriber id
     * @throws EntitlementException throws, if fails
     */
    @Override
    public void deleteSubscriber(String subscriberId) throws EntitlementException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        if (subscriberId == null) {
            log.error("Subscriber Id can not be null");
            throw new EntitlementException("Subscriber Id can not be null");
        }

        if (EntitlementConstants.PDP_SUBSCRIBER_ID.equals(subscriberId.trim())) {
            log.error("Can not delete PDP publisher");
            throw new EntitlementException("Can not delete PDP publisher");
        }

        try {
            PreparedStatement deleteSubscriberPrepStmt = connection.prepareStatement(DELETE_SUBSCRIBER_SQL);
            deleteSubscriberPrepStmt.setString(1, subscriberId);
            deleteSubscriberPrepStmt.setInt(2, tenantId);
            deleteSubscriberPrepStmt.executeUpdate();
            IdentityDatabaseUtil.closeStatement(deleteSubscriberPrepStmt);

            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            log.error("Error while deleting subscriber details", e);
            throw new EntitlementException("Error while deleting subscriber details", e);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }


    /**
     * Retrieves a subscriber
     *
     * @param id subscriber id
     * @param returnSecrets whether the function should return secrets or not
     * @return PublisherDataHolder
     * @throws EntitlementException throws, if fails
     */
    @Override
    public PublisherDataHolder retrieveSubscriber(String id, boolean returnSecrets) throws EntitlementException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        PreparedStatement getSubscriberPrepStmt = null;
        ResultSet rs1 = null;

        try {
            getSubscriberPrepStmt = connection.prepareStatement(GET_SUBSCRIBER_SQL);
            getSubscriberPrepStmt.setString(1, id);
            getSubscriberPrepStmt.setInt(2, tenantId);
            rs1 = getSubscriberPrepStmt.executeQuery();
            if (rs1.next()) {
                return new PublisherDataHolder(rs1, returnSecrets);
            } else {
                return null;
            }

        } catch (SQLException e) {
            log.error("Error while retrieving subscriber details of id : " + id, e);
            throw new EntitlementException("Error while retrieving subscriber details of id : " + id, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, rs1, getSubscriberPrepStmt);
        }
    }


    /**
     * Retrieves subscriber ids
     *
     * @param searchString search string for subscribers
     * @return string array of subscriber ids
     * @throws EntitlementException throws, if fails
     */
    @Override
    public String[] retrieveSubscriberIds(String searchString) throws EntitlementException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        PreparedStatement getSubscriberIdsPrepStmt = null;
        ResultSet subscriberIds = null;

        try {
            getSubscriberIdsPrepStmt = connection.prepareStatement(GET_SUBSCRIBER_IDS_SQL);
            getSubscriberIdsPrepStmt.setInt(1, tenantId);
            subscriberIds = getSubscriberIdsPrepStmt.executeQuery();

            List<String> subscriberIDList = new ArrayList<>();
            searchString = searchString.replace("*", ".*");
            Pattern pattern = Pattern.compile(searchString, Pattern.CASE_INSENSITIVE);

            if (subscriberIds.next()) {
                do {
                    String id = subscriberIds.getString(EntitlementTableColumns.SUBSCRIBER_ID);
                    Matcher matcher = pattern.matcher(id);
                    if (!matcher.matches()) {
                        continue;
                    }
                    subscriberIDList.add(id);

                } while (subscriberIds.next());

                return subscriberIDList.toArray(new String[0]);

            } else {
                return null;
            }

        } catch (SQLException e) {
            log.error("Error while retrieving subscriber of ids", e);
            throw new EntitlementException("Error while retrieving subscriber ids", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, subscriberIds, getSubscriberIdsPrepStmt);
        }
    }


    private void populateProperties(PublisherDataHolder holder,
                                    PublisherDataHolder oldHolder) {

        PublisherPropertyDTO[] propertyDTOs = holder.getPropertyDTOs();

        for (PublisherPropertyDTO dto : propertyDTOs) {
            if (dto.getId() != null && dto.getValue() != null && !dto.getValue().trim().isEmpty()) {

                if (dto.isSecret()) {
                    PublisherPropertyDTO propertyDTO = null;
                    if (oldHolder != null) {
                        propertyDTO = oldHolder.getPropertyDTO(dto.getId());
                    }
                    if (propertyDTO == null || !propertyDTO.getValue().equalsIgnoreCase(dto.getValue())) {
                        try {
                            String encryptedValue = CryptoUtil.getDefaultCryptoUtil().
                                    encryptAndBase64Encode(dto.getValue().getBytes());
                            dto.setValue(encryptedValue);
                        } catch (CryptoException e) {
                            log.error("Error while encrypting secret value of subscriber. " +
                                    "Secret would not be persist.", e);
                        }
                    }
                }
            }
        }
    }

}
