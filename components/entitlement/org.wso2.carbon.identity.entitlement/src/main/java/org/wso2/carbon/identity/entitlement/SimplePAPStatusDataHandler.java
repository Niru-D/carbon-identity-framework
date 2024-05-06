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

import org.wso2.carbon.identity.entitlement.common.EntitlementConstants;
import org.wso2.carbon.identity.entitlement.dao.RegistryStatusDataDAOImpl;
import org.wso2.carbon.identity.entitlement.dao.StatusDataDAO;
import org.wso2.carbon.identity.entitlement.dto.StatusHolder;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;


/**
 * Default implementation of the PAPStatusDataHandler
 */
public class SimplePAPStatusDataHandler implements PAPStatusDataHandler {


    @Override
    public void init(Properties properties) {

    }


    @Override
    public void handle(String about, String key, List<StatusHolder> statusHolder)
            throws EntitlementException {

        //TODO - Change
        StatusDataDAO statusDataHandler = new RegistryStatusDataDAOImpl();
        if(EntitlementConstants.Status.ABOUT_POLICY.equals(about)){
            statusDataHandler.handlePolicyStatusData(key, statusHolder);
        }else{
            statusDataHandler.handleSubscriberStatusData(key, statusHolder);
        }

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

        StatusHolder[] statusHolders;
        //TODO - Change
        StatusDataDAO statusDataHandler = new RegistryStatusDataDAOImpl();
        if (EntitlementConstants.Status.ABOUT_POLICY.equals(about)) {
            statusHolders = statusDataHandler.getPolicyStatusData(key, type, searchString);
        } else {
            statusHolders = statusDataHandler.getSubscriberStatusData(key, type, searchString);
        }
        return statusHolders;
    }

}
