/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.entitlement.dao;


/**
 * TODO
 * SQL Queries used in {@link }.
 */
public class SQLQueries {


    /**
     * DB queries related to PAP policy store
     */

    public static final String CREATE_PAP_POLICY_SQL = "INSERT INTO IDN_XACML_POLICY (POLICY_ID, VERSION, TENANT_ID, " +
            "IS_IN_PDP, IS_IN_PAP, POLICY, IS_ACTIVE, POLICY_TYPE, POLICY_EDITOR, POLICY_ORDER, LAST_MODIFIED_TIME, " +
            "LAST_MODIFIED_USER) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)";

    public static final String CREATE_PAP_POLICY_REFS_SQL = "INSERT INTO IDN_XACML_POLICY_REFERENCE " +
            "(REFERENCE, POLICY_ID, VERSION, TENANT_ID) VALUES (?, ?, ?, ?)";

    public static final String CREATE_PAP_POLICY_SET_REFS_SQL = "INSERT INTO IDN_XACML_POLICY_SET_REFERENCE " +
            "(SET_REFERENCE, POLICY_ID, VERSION, TENANT_ID) VALUES (?, ?, ?, ?)";

    public static final String CREATE_PAP_POLICY_ATTRIBUTES_SQL = "INSERT INTO IDN_XACML_POLICY_ATTRIBUTE " +
            "(NAME, VALUE, POLICY_ID, VERSION, TENANT_ID) VALUES (?, ?, ?, ?, ?)";

    public static final String CREATE_PAP_POLICY_EDITOR_DATA_SQL = "INSERT INTO IDN_XACML_POLICY_EDITOR_DATA " +
            "(NAME, DATA, POLICY_ID, VERSION, TENANT_ID) VALUES (?, ?, ?, ?, ?)";

    public static final String GET_PAP_POLICY_IDS_SQL = "SELECT DISTINCT POLICY_ID FROM IDN_XACML_POLICY WHERE " +
            "TENANT_ID=? AND IS_IN_PAP=?";

    public static final String GET_PAP_POLICY_SQL = "SELECT * FROM IDN_XACML_POLICY WHERE IS_IN_PAP = ? AND " +
            "TENANT_ID = ? AND POLICY_ID=? AND VERSION =(SELECT MAX(VERSION) FROM IDN_XACML_POLICY WHERE " +
            "POLICY_ID = ? AND TENANT_ID=?)";

    public static final String GET_PAP_POLICY_REFS_SQL = "SELECT * FROM IDN_XACML_POLICY_REFERENCE WHERE " +
            "TENANT_ID=? AND POLICY_ID=? AND VERSION=?";

    public static final String GET_PAP_POLICY_SET_REFS_SQL = "SELECT * FROM IDN_XACML_POLICY_SET_REFERENCE WHERE " +
            "TENANT_ID=? AND POLICY_ID=? AND VERSION=?";

    public static final String GET_PAP_POLICY_EDITOR_DATA_SQL = "SELECT * FROM IDN_XACML_POLICY_EDITOR_DATA WHERE " +
            "POLICY_ID=? AND VERSION=? AND TENANT_ID=?";

    public static final String GET_PAP_POLICY_META_DATA_SQL = "SELECT * FROM IDN_XACML_POLICY_ATTRIBUTE WHERE " +
            "POLICY_ID=? AND VERSION=? AND TENANT_ID=?";

    public static final String GET_PAP_POLICY_BY_VERSION_SQL = "SELECT * FROM IDN_XACML_POLICY WHERE IS_IN_PAP = ? " +
            "AND TENANT_ID = ? AND POLICY_ID=? AND VERSION = ?";

    public static final String GET_ALL_PAP_POLICIES_SQL = "SELECT t1.* FROM IDN_XACML_POLICY t1 WHERE t1.IS_IN_PAP = ? " +
            "AND t1.TENANT_ID = ? AND t1.VERSION =(SELECT MAX(VERSION) FROM IDN_XACML_POLICY t2 WHERE " +
            "t2.POLICY_ID = t1.POLICY_ID AND t2.TENANT_ID=?)";

    public static final String DELETE_PAP_POLICY_SQL = "UPDATE IDN_XACML_POLICY SET IS_IN_PAP=? WHERE POLICY_ID=? " +
            "AND IS_IN_PDP=? AND TENANT_ID=?";

    public static final String DELETE_PAP_POLICY_BY_VERSION_SQL = "UPDATE IDN_XACML_POLICY SET IS_IN_PAP=? WHERE " +
            "POLICY_ID=? AND VERSION=? AND TENANT_ID=?";

    public static final String DELETE_UNPUBLISHED_POLICY_VERSIONS_SQL = "DELETE FROM IDN_XACML_POLICY WHERE " +
            "POLICY_ID=? AND TENANT_ID=? AND IS_IN_PDP=?";

    public static final String DELETE_POLICY_SQL = "DELETE FROM IDN_XACML_POLICY WHERE POLICY_ID=? AND TENANT_ID=?";

    public static final String DELETE_POLICY_VERSION_SQL = "DELETE FROM IDN_XACML_POLICY WHERE POLICY_ID=? AND " +
            "TENANT_ID=? AND VERSION=?";


    /**
     * DB queries related to PDP policy store
     */

    public static final String CREATE_POLICY_COMBINING_ALGORITHM_SQL = "INSERT INTO IDN_XACML_CONFIG " +
            "(CONFIG_VALUE, TENANT_ID, CONFIG_KEY) VALUES (?, ?, ?)";

    public static final String GET_POLICY_PDP_PRESENCE_SQL = "SELECT * FROM IDN_XACML_POLICY WHERE POLICY_ID=? AND " +
            "IS_IN_PDP=? AND TENANT_ID=?";

    public static final String GET_POLICY_PDP_PRESENCE_BY_VERSION_SQL = "SELECT * FROM IDN_XACML_POLICY WHERE " +
            "POLICY_ID=? AND IS_IN_PDP=? AND TENANT_ID=? AND VERSION=?";

    public static final String GET_ALL_PDP_POLICIES_SQL = "SELECT * FROM IDN_XACML_POLICY WHERE TENANT_ID=? AND " +
            "IS_IN_PDP=?";

    public static final String GET_PUBLISHED_POLICY_VERSION_SQL = "SELECT VERSION FROM IDN_XACML_POLICY WHERE " +
            "POLICY_ID=? AND TENANT_ID=? AND IS_IN_PDP=?";

    public static final String GET_ACTIVE_STATUS_AND_ORDER_SQL = "SELECT * FROM IDN_XACML_POLICY WHERE POLICY_ID=? " +
            "AND TENANT_ID=? AND IS_IN_PDP=?";

    public static final String GET_POLICY_COMBINING_ALGORITHM_SQL = "SELECT * FROM IDN_XACML_CONFIG WHERE TENANT_ID=? " +
            "AND CONFIG_KEY=?";

    public static final String UPDATE_ACTIVE_STATUS_SQL = "UPDATE IDN_XACML_POLICY SET IS_ACTIVE=? WHERE POLICY_ID=? " +
            "AND TENANT_ID=? AND VERSION=?";

    public static final String UPDATE_ORDER_SQL = "UPDATE IDN_XACML_POLICY SET POLICY_ORDER=? WHERE POLICY_ID=? " +
            "AND TENANT_ID=? AND VERSION=?";

    public static final String DELETE_PUBLISHED_VERSIONS_SQL = "UPDATE IDN_XACML_POLICY SET IS_IN_PDP=?, IS_ACTIVE=?, " +
            "POLICY_ORDER=? WHERE POLICY_ID=? AND TENANT_ID=? AND IS_IN_PDP=?";

    public static final String PUBLISH_POLICY_VERSION_SQL = "UPDATE IDN_XACML_POLICY SET IS_IN_PDP=? WHERE POLICY_ID=? " +
            "AND TENANT_ID=? AND VERSION=?";

    public static final String RESTORE_ACTIVE_STATUS_AND_ORDER_SQL = "UPDATE IDN_XACML_POLICY SET IS_ACTIVE=?, " +
            "POLICY_ORDER=? WHERE POLICY_ID=? AND TENANT_ID=? AND VERSION=?";

    public static final String UPDATE_POLICY_COMBINING_ALGORITHM_SQL = "UPDATE IDN_XACML_CONFIG SET CONFIG_VALUE=? " +
            "WHERE TENANT_ID=? AND CONFIG_KEY=?";

    public static final String DELETE_UNUSED_POLICY_SQL = "DELETE FROM IDN_XACML_POLICY WHERE POLICY_ID=? AND " +
            "TENANT_ID=? AND IS_IN_PAP=? AND IS_IN_PDP=?";


    /**
     * DB queries related to subscribers
     */

    public static final String CREATE_SUBSCRIBER_SQL = "INSERT INTO IDN_XACML_SUBSCRIBER (SUBSCRIBER_ID, TENANT_ID, " +
            "ENTITLEMENT_MODULE_NAME) VALUES (?,?,?)";

    public static final String CREATE_SUBSCRIBER_PROPERTIES_SQL = "INSERT INTO IDN_XACML_SUBSCRIBER_PROPERTY " +
            "(PROPERTY_ID, DISPLAY_NAME, VALUE, IS_REQUIRED, DISPLAY_ORDER, IS_SECRET, MODULE, SUBSCRIBER_ID, " +
            "TENANT_ID) VALUES (?,?,?,?,?,?,?,?,?)";

    public static final String GET_SUBSCRIBER_EXISTENCE_SQL = "SELECT * FROM IDN_XACML_SUBSCRIBER WHERE " +
            "SUBSCRIBER_ID=? AND TENANT_ID=?";

    public static final String GET_SUBSCRIBER_SQL = "SELECT s.SUBSCRIBER_ID, s.TENANT_ID, s.ENTITLEMENT_MODULE_NAME, " +
            "p.PROPERTY_ID, p.DISPLAY_NAME, p.VALUE, p.IS_REQUIRED, p.DISPLAY_ORDER, p.IS_SECRET, " +
            "p.MODULE FROM IDN_XACML_SUBSCRIBER s INNER JOIN IDN_XACML_SUBSCRIBER_PROPERTY p ON " +
            "s.SUBSCRIBER_ID = p.SUBSCRIBER_ID AND s.TENANT_ID = p.TENANT_ID WHERE s.SUBSCRIBER_ID = ? " +
            "AND s.TENANT_ID = ?";

    public static final String GET_SUBSCRIBER_IDS_SQL = "SELECT SUBSCRIBER_ID FROM IDN_XACML_SUBSCRIBER WHERE " +
            "TENANT_ID=?";

    public static final String UPDATE_SUBSCRIBER_MODULE_SQL = "UPDATE IDN_XACML_SUBSCRIBER SET " +
            "ENTITLEMENT_MODULE_NAME=? WHERE SUBSCRIBER_ID=? AND TENANT_ID=?";

    public static final String UPDATE_SUBSCRIBER_PROPERTIES_SQL = "UPDATE IDN_XACML_SUBSCRIBER_PROPERTY SET VALUE=? " +
            "WHERE SUBSCRIBER_ID=? AND TENANT_ID=? AND PROPERTY_ID=?";

    public static final String DELETE_SUBSCRIBER_SQL = "DELETE FROM IDN_XACML_SUBSCRIBER WHERE SUBSCRIBER_ID=? " +
            "AND TENANT_ID=?";


    /**
     * DB queries related to status
     */

    public static final String CREATE_POLICY_STATUS_SQL = "INSERT INTO IDN_XACML_STATUS (TYPE, SUCCESS, USER, " +
            "TARGET, TARGET_ACTION, TIME_INSTANCE, MESSAGE, POLICY_ID, POLICY_TENANT_ID, POLICY_VERSION) VALUES " +
            "(?,?,?,?,?,?,?,?,?,?)";

    public static final String CREATE_SUBSCRIBER_STATUS_SQL = "INSERT INTO IDN_XACML_STATUS (TYPE, SUCCESS, USER, " +
            "TARGET, TARGET_ACTION, TIME_INSTANCE, MESSAGE, SUBSCRIBER_ID, SUBSCRIBER_TENANT_ID) VALUES " +
            "(?,?,?,?,?,?,?,?,?)";

    public static final String GET_POLICY_STATUS_SQL = "SELECT * FROM IDN_XACML_STATUS WHERE POLICY_ID=? AND " +
            "POLICY_TENANT_ID=?";

    public static final String GET_SUBSCRIBER_STATUS_SQL = "SELECT * FROM IDN_XACML_STATUS WHERE SUBSCRIBER_ID=? " +
            "AND SUBSCRIBER_TENANT_ID=?";

    public static final String GET_POLICY_STATUS_COUNT_SQL = "SELECT COUNT(*) AS COUNT FROM IDN_XACML_STATUS WHERE " +
            "POLICY_ID=? AND POLICY_TENANT_ID=?";

    public static final String GET_SUBSCRIBER_STATUS_COUNT_SQL = "SELECT COUNT(*) AS COUNT FROM IDN_XACML_STATUS " +
            "WHERE SUBSCRIBER_ID=? AND SUBSCRIBER_TENANT_ID=?";

    public static final String DELETE_POLICY_STATUS_SQL = "DELETE FROM IDN_XACML_STATUS WHERE POLICY_ID=? AND " +
            "POLICY_TENANT_ID=?";

    public static final String DELETE_SUBSCRIBER_STATUS_SQL = "DELETE FROM IDN_XACML_STATUS WHERE SUBSCRIBER_ID=? " +
            "AND SUBSCRIBER_TENANT_ID=?";

    public static final String DELETE_OLD_POLICY_STATUSES_SQL = "DELETE FROM IDN_XACML_STATUS WHERE POLICY_ID=? AND " +
            "POLICY_TENANT_ID=? ORDER BY STATUS_ID ASC LIMIT ?";

    public static final String DELETE_OLD_SUBSCRIBER_STATUSES_SQL = "DELETE FROM IDN_XACML_STATUS WHERE " +
            "SUBSCRIBER_ID=? AND SUBSCRIBER_TENANT_ID=? ORDER BY STATUS_ID ASC LIMIT ?";


    /**
     * DB queries related to policy version management
     */

    public static final String GET_LATEST_POLICY_VERSION_SQL = "SELECT MAX(VERSION) AS VERSION FROM IDN_XACML_POLICY " +
            "WHERE POLICY_ID=? AND TENANT_ID=? AND IS_IN_PAP=?";

    public static final String GET_POLICY_VERSIONS_SQL = "SELECT VERSION FROM IDN_XACML_POLICY WHERE TENANT_ID=? AND " +
            "POLICY_ID=?";

}
