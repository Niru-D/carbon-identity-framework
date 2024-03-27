/*
 *  Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.entitlement;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.entitlement.common.EntitlementConstants;
import org.wso2.carbon.identity.entitlement.dto.PublisherPropertyDTO;
import org.wso2.carbon.identity.entitlement.dto.StatusHolder;
import org.wso2.carbon.identity.entitlement.internal.EntitlementServiceComponent;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.RegistryConstants;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * TODO
 */
public class SimplePAPStatusDataHandler implements PAPStatusDataHandler {

    private static final int SEARCH_BY_USER = 0;
    private static final int SEARCH_BY_POLICY = 1;
    private static Log log = LogFactory.getLog(SimplePAPStatusDataHandler.class);
    private int DEFAULT_MAX_RECODES = 50;
    private int maxRecodes;

    @Override
    public void init(Properties properties) {
        String maxRecodesString = (String) properties.get("maxRecodesToPersist");
        if (maxRecodesString != null) {
            try {
                maxRecodes = Integer.parseInt(maxRecodesString);
            } catch (Exception e) {
                //ignore
            }
        }
        if (maxRecodes == 0) {
            maxRecodes = DEFAULT_MAX_RECODES;
        }
    }

    @Override
    public void handle(String about, String key, List<StatusHolder> statusHolder)
            throws EntitlementException {

        //If the action is DELETE_POLICY, delete the policy or the subscriber status
        for (StatusHolder holder : statusHolder) {
            if (EntitlementConstants.StatusTypes.DELETE_POLICY.equals(holder.getType())) {
                deletedPersistedDataFromNewRDBMS(about, key);
                return;
            }
        }
        persistStatusToNewRDBMS(about, key, statusHolder);
    }


    @Override
    public void handle(String about, StatusHolder statusHolder) throws EntitlementException {
        List<StatusHolder> list = new ArrayList<StatusHolder>();
        list.add(statusHolder);
        handle(about, statusHolder.getKey(), list);
    }


    @Override
    public StatusHolder[] getStatusData(String about, String key, String type, String searchString)
            throws EntitlementException {

        if (EntitlementConstants.Status.ABOUT_POLICY.equals(about)) {

            List<StatusHolder> holders = readStatus(key, EntitlementConstants.Status.ABOUT_POLICY);
            List<StatusHolder> filteredHolders = new ArrayList<StatusHolder>();
            if (holders != null) {
                searchString = searchString.replace("*", ".*");
                Pattern pattern = Pattern.compile(searchString, Pattern.CASE_INSENSITIVE);
                for (StatusHolder holder : holders) {
                    String id = holder.getUser();
                    Matcher matcher = pattern.matcher(id);
                    if (!matcher.matches()) {
                        continue;
                    }
                    if (type != null && type.equals(holder.getType())) {
                        filteredHolders.add(holder);
                    } else if (type == null) {
                        filteredHolders.add(holder);
                    }
                }
            }
            return filteredHolders.toArray(new StatusHolder[filteredHolders.size()]);

        } else {

            List<StatusHolder> filteredHolders = new ArrayList<StatusHolder>();
            List<StatusHolder> holders = readStatus(key, EntitlementConstants.Status.ABOUT_SUBSCRIBER);
            if (holders != null) {
                searchString = searchString.replace("*", ".*");
                Pattern pattern = Pattern.compile(searchString, Pattern.CASE_INSENSITIVE);
                for (StatusHolder holder : holders) {
                    String id = holder.getTarget();
                    Matcher matcher = pattern.matcher(id);
                    if (!matcher.matches()) {
                        continue;
                    }
                    filteredHolders.add(holder);
                }
            }
            return filteredHolders.toArray(new StatusHolder[filteredHolders.size()]);
        }
    }


    private synchronized void deletedPersistedDataFromNewRDBMS(String about, String key) throws EntitlementException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        try {
            PreparedStatement deleteStatusPrepStmt = null;
            if (EntitlementConstants.Status.ABOUT_POLICY.equals(about)){
                deleteStatusPrepStmt = connection.prepareStatement(
                        "DELETE FROM IDN_XACML_STATUS WHERE POLICY_ID=? AND POLICY_TENANT_ID=?");
            }else{
                deleteStatusPrepStmt = connection.prepareStatement(
                        "DELETE FROM IDN_XACML_STATUS WHERE SUBSCRIBER_ID=? AND SUBSCRIBER_TENANT_ID=?");
            }
            deleteStatusPrepStmt.setString(1, key);
            deleteStatusPrepStmt.setInt(2, tenantId);
            deleteStatusPrepStmt.executeUpdate();
            IdentityDatabaseUtil.closeStatement(deleteStatusPrepStmt);

            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            log.error(e);
            throw new EntitlementException("Error while persisting policy status", e);
        }finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }


    private synchronized void persistStatusToNewRDBMS(String about, String key, List<StatusHolder> statusHolders)
            throws EntitlementException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(true);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        try {
            boolean useLastStatusOnly = Boolean.parseBoolean(
                    IdentityUtil.getProperty(EntitlementConstants.PROP_USE_LAST_STATUS_ONLY));

            if(statusHolders != null && !statusHolders.isEmpty()){

                if (useLastStatusOnly) {

                    //Delete the previous status
                    PreparedStatement deleteStatusPrepStmt = null;
                    if (EntitlementConstants.Status.ABOUT_POLICY.equals(about)){
                        deleteStatusPrepStmt = connection.prepareStatement(
                                "DELETE FROM IDN_XACML_STATUS WHERE POLICY_ID=? AND POLICY_TENANT_ID=?");
                    }else{
                        deleteStatusPrepStmt = connection.prepareStatement(
                                "DELETE FROM IDN_XACML_STATUS WHERE SUBSCRIBER_ID=? AND SUBSCRIBER_TENANT_ID=?");
                    }
                    deleteStatusPrepStmt.setString(1, key);
                    deleteStatusPrepStmt.setInt(2, tenantId);
                    deleteStatusPrepStmt.executeUpdate();
                    IdentityDatabaseUtil.closeStatement(deleteStatusPrepStmt);

                }

                //Add new status to the database
                PreparedStatement addStatusPrepStmt = null;
                if(EntitlementConstants.Status.ABOUT_POLICY.equals(about)) {
                    addStatusPrepStmt = connection.prepareStatement(
                            "INSERT INTO IDN_XACML_STATUS (TYPE, SUCCESS, USER, TARGET, TARGET_ACTION," +
                                    "TIME_INSTANCE, MESSAGE, POLICY_ID, POLICY_TENANT_ID, POLICY_VERSION) VALUES " +
                                    "(?,?,?,?,?,?,?,?,?,?)");
                }else{
                    addStatusPrepStmt = connection.prepareStatement(
                            "INSERT INTO IDN_XACML_STATUS (TYPE, SUCCESS, USER, TARGET, TARGET_ACTION," +
                                    "TIME_INSTANCE, MESSAGE, SUBSCRIBER_ID, SUBSCRIBER_TENANT_ID) VALUES " +
                                    "(?,?,?,?,?,?,?,?,?)");
                }

                for(StatusHolder statusHolder : statusHolders){

                    String message = "";
                    if (statusHolder.getMessage() != null) {
                        message = statusHolder.getMessage();
                    }
                    String target = "";
                    if (statusHolder.getTarget() != null) {
                        target = statusHolder.getTarget();
                    }
                    String targetAction = "";
                    if (statusHolder.getTargetAction() != null) {
                        targetAction = statusHolder.getTargetAction();
                    }
                    int version = -1;
                    if (statusHolder.getVersion() != null) {
                        version = Integer.parseInt(statusHolder.getVersion());
                    }

                    addStatusPrepStmt.setString(1, statusHolder.getType());
                    addStatusPrepStmt.setInt(2, statusHolder.isSuccess() ? 1 : 0);
                    addStatusPrepStmt.setString(3, statusHolder.getUser());
                    addStatusPrepStmt.setString(4, target);
                    addStatusPrepStmt.setString(5, targetAction);
                    addStatusPrepStmt.setString(6, Long.toString(System.currentTimeMillis()));
                    addStatusPrepStmt.setString(7, message);
                    addStatusPrepStmt.setString(8, key);
                    addStatusPrepStmt.setInt(9, tenantId);

                    if(EntitlementConstants.Status.ABOUT_POLICY.equals(about)) {
                        addStatusPrepStmt.setInt(10, version);
                    }

                    addStatusPrepStmt.addBatch();
                }
                assert addStatusPrepStmt != null;
                addStatusPrepStmt.executeBatch();
                IdentityDatabaseUtil.closeStatement(addStatusPrepStmt);


                if(!useLastStatusOnly){
                    //Get the existing status count
                    PreparedStatement getStatusCountPrepStmt = null;
                    if (EntitlementConstants.Status.ABOUT_POLICY.equals(about)){
                        getStatusCountPrepStmt = connection.prepareStatement(
                                "SELECT COUNT(*) AS COUNT FROM IDN_XACML_STATUS WHERE POLICY_ID=? AND POLICY_TENANT_ID=?");
                    }else{
                        getStatusCountPrepStmt = connection.prepareStatement(
                                "SELECT COUNT(*) AS COUNT FROM IDN_XACML_STATUS WHERE SUBSCRIBER_ID=? AND " +
                                        "SUBSCRIBER_TENANT_ID=?");
                    }
                    getStatusCountPrepStmt.setString(1, key);
                    getStatusCountPrepStmt.setInt(2, tenantId);
                    ResultSet count = getStatusCountPrepStmt.executeQuery();
                    int statusCount = 0;
                    if(count.next()){
                        statusCount = count.getInt("COUNT");
                    }
                    IdentityDatabaseUtil.closeResultSet(count);
                    IdentityDatabaseUtil.closeStatement(getStatusCountPrepStmt);

                    //Delete old status data
                    if(statusCount > maxRecodes){

                        int oldRecordsCount = statusCount - maxRecodes;
                        PreparedStatement deleteOldRecordsPrepStmt = null;
                        if (EntitlementConstants.Status.ABOUT_POLICY.equals(about)){
                            deleteOldRecordsPrepStmt = connection.prepareStatement(
                                    "DELETE FROM IDN_XACML_STATUS WHERE POLICY_ID=? AND POLICY_TENANT_ID=?" +
                                            " ORDER BY STATUS_ID ASC LIMIT ?");
                        }else{
                            deleteOldRecordsPrepStmt = connection.prepareStatement(
                                    "DELETE FROM IDN_XACML_STATUS WHERE SUBSCRIBER_ID=? AND SUBSCRIBER_TENANT_ID=?" +
                                            " ORDER BY STATUS_ID ASC LIMIT ?");
                        }
                        deleteOldRecordsPrepStmt.setString(1, key);
                        deleteOldRecordsPrepStmt.setInt(2, tenantId);
                        deleteOldRecordsPrepStmt.setInt(3, oldRecordsCount);
                        deleteOldRecordsPrepStmt.executeUpdate();
                        IdentityDatabaseUtil.closeStatement(deleteOldRecordsPrepStmt);
                    }
                }
            }

            IdentityDatabaseUtil.commitTransaction(connection);

        } catch (SQLException e) {
            IdentityDatabaseUtil.rollbackTransaction(connection);
            log.error(e);
            throw new EntitlementException("Error while persisting policy status", e);
        }finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }

    }

    private synchronized List<StatusHolder> readStatus(String key, String about) throws EntitlementException {

        Connection connection = IdentityDatabaseUtil.getDBConnection(false);
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        PreparedStatement getStatusPrepStmt = null;
        ResultSet statusSet = null;
        List<StatusHolder> statusHolders = new ArrayList<StatusHolder>();

        try {
            if(EntitlementConstants.Status.ABOUT_POLICY.equals(about)) {
                getStatusPrepStmt = connection.prepareStatement(
                        "SELECT * FROM IDN_XACML_STATUS WHERE POLICY_ID=? AND POLICY_TENANT_ID=?");
            }else{
                getStatusPrepStmt = connection.prepareStatement(
                        "SELECT * FROM IDN_XACML_STATUS WHERE SUBSCRIBER_ID=? AND SUBSCRIBER_TENANT_ID=?");
            }
            getStatusPrepStmt.setString(1, key);
            getStatusPrepStmt.setInt(2, tenantId);
            statusSet = getStatusPrepStmt.executeQuery();

            if(statusSet.next()){
                do {
                    StatusHolder statusHolder = new StatusHolder(about);

                    if(EntitlementConstants.Status.ABOUT_POLICY.equals(about)){
                        statusHolder.setKey(statusSet.getString("POLICY_ID"));
                    }else{
                        statusHolder.setKey(statusSet.getString("SUBSCRIBER_ID"));
                    }
                    statusHolder.setType(statusSet.getString("TYPE"));
                    statusHolder.setSuccess(statusSet.getInt("SUCCESS") == 1);
                    statusHolder.setUser(statusSet.getString("USER"));
                    statusHolder.setTarget(statusSet.getString("TARGET"));
                    statusHolder.setTargetAction(statusSet.getString("TARGET_ACTION"));
                    statusHolder.setTimeInstance(statusSet.getString("TIME_INSTANCE"));
                    statusHolder.setMessage(statusSet.getString("MESSAGE"));

                    String version;
                    if(statusSet.getInt("POLICY_VERSION")==-1){
                        version = "";
                    }else{
                        version = Integer.toString(statusSet.getInt("POLICY_VERSION"));
                    }
                    statusHolder.setVersion(version);

                    statusHolders.add(statusHolder);

                } while (statusSet.next());
            }

            return statusHolders;

        } catch (SQLException e) {
            log.error(e);
            throw new EntitlementException("Error while persisting policy status", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, statusSet, getStatusPrepStmt);
        }
    }


}
