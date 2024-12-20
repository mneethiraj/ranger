/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
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

package org.apache.ranger.services.hive.client;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.metastore.HiveMetaStoreClient;
import org.apache.hadoop.hive.metastore.api.FieldSchema;
import org.apache.hadoop.hive.metastore.api.MetaException;
import org.apache.ranger.plugin.client.BaseClient;
import org.apache.ranger.plugin.client.HadoopException;
import org.apache.ranger.plugin.util.PasswordUtils;
import org.apache.thrift.TException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;

import java.io.Closeable;
import java.io.File;
import java.net.MalformedURLException;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.SQLTimeoutException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class HiveClient extends BaseClient implements Closeable {
    private static final Logger LOG = LoggerFactory.getLogger(HiveClient.class);

    private static final String ERR_MSG = "You can still save the repository and start creating "
            + "policies, but you would not be able to use autocomplete for "
            + "resource names. Check ranger_admin.log for more info.";

    private Connection          con;
    private HiveMetaStoreClient hiveClient;
    private String              hiveSiteFilePath;
    private boolean             enableHiveMetastoreLookup;

    public HiveClient(String serviceName) throws Exception {
        super(serviceName, null);

        initHive();
    }

    public HiveClient(String serviceName, Map<String, String> connectionProp) throws Exception {
        super(serviceName, connectionProp);

        initHive();
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.err.println("USAGE: java " + HiveClient.class.getName() + " dataSourceName <databaseName> <tableName> <columnName>");

            System.exit(1);
        }

        try (HiveClient hc = new HiveClient(args[0])) {
            if (args.length == 2) {
                try {
                    List<String> dbList = hc.getDatabaseList(args[1], null);

                    if (CollectionUtils.isEmpty(dbList)) {
                        System.out.println("No database found with db filter [" + args[1] + "]");
                    } else {
                        if (CollectionUtils.isNotEmpty(dbList)) {
                            for (String str : dbList) {
                                System.out.println("database: " + str);
                            }
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else if (args.length == 3) {
                List<String> tableList = hc.getTableList(args[2], null, null);

                if (tableList.isEmpty()) {
                    System.out.println("No tables found under database[" + args[1] + "] with table filter [" + args[2] + "]");
                } else {
                    for (String str : tableList) {
                        System.out.println("Table: " + str);
                    }
                }
            } else if (args.length == 4) {
                List<String> columnList = hc.getColumnList(args[3], null, null, null);

                if (columnList.isEmpty()) {
                    System.out.println("No columns found for db:" + args[1] + ", table: [" + args[2] + "], with column filter [" + args[3] + "]");
                } else {
                    for (String str : columnList) {
                        System.out.println("Column: " + str);
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Map<String, Object> connectionTest(String serviceName, Map<String, String> connectionProperties) throws Exception {
        Map<String, Object> responseData = new HashMap<>();

        try (HiveClient connectionObj = new HiveClient(serviceName, connectionProperties)) {
            List<String> testResult         = connectionObj.getDatabaseList("*", null);
            boolean      connectivityStatus = (testResult != null && !testResult.isEmpty());

            if (connectivityStatus) {
                String successMsg = "ConnectionTest Successful";

                generateResponseDataMap(connectivityStatus, successMsg, successMsg, null, null, responseData);
            } else {
                String failureMsg = "Unable to retrieve any databases using given parameters.";

                generateResponseDataMap(connectivityStatus, failureMsg, failureMsg + ERR_MSG, null, null, responseData);
            }
        } catch (Exception e) {
            throw e;
        }

        return responseData;
    }

    public void initHive() throws Exception {
        enableHiveMetastoreLookup = getConfigHolder().isEnableHiveMetastoreLookup();
        hiveSiteFilePath          = getConfigHolder().getHiveSiteFilePath();

        boolean isKerberosAuth = getConfigHolder().isKerberosAuthentication();

        if (isKerberosAuth) {
            LOG.info("Secured Mode: JDBC Connection done with preAuthenticated Subject");

            Subject.doAs(getLoginSubject(), (PrivilegedExceptionAction<Void>) () -> {
                initConnection();
                return null;
            });
        } else {
            LOG.info("Since Password is NOT provided, Trying to use UnSecure client with username and password");

            final String userName = getConfigHolder().getUserName();
            final String password = getConfigHolder().getPassword();

            Subject.doAs(getLoginSubject(), (PrivilegedExceptionAction<Void>) () -> {
                initConnection(userName, password);
                return null;
            });
        }
    }

    public List<String> getDatabaseList(String databaseMatching, final List<String> databaseList) throws HadoopException {
        final String       dbMatching = databaseMatching;

        return Subject.doAs(getLoginSubject(), (PrivilegedAction<List<String>>) () -> {
            List<String> ret;

            try {
                if (enableHiveMetastoreLookup) {
                    ret = getDBListFromHM(dbMatching, databaseList);
                } else {
                    ret = getDBList(dbMatching, databaseList);
                }
            } catch (HadoopException he) {
                LOG.error("<== HiveClient getDatabaseList() :Unable to get the Database List", he);

                throw he;
            }

            return ret;
        });
    }

    public List<String> getTableList(String tableNameMatching, List<String> databaseList, List<String> tblNameList) throws HadoopException {
        final List<String> tblList = tblNameList;

        return Subject.doAs(getLoginSubject(), (PrivilegedAction<List<String>>) () -> {
            List<String> ret;

            try {
                if (enableHiveMetastoreLookup) {
                    ret = getTblListFromHM(tableNameMatching, databaseList, tblList);
                } else {
                    ret = getTblList(tableNameMatching, databaseList, tblList);
                }
            } catch (HadoopException he) {
                LOG.error("<== HiveClient getTableList() :Unable to get the Table List", he);

                throw he;
            }

            return ret;
        });
    }

    public List<String> getViewList(String database, String viewNameMatching) {
        return null;
    }

    public List<String> getUDFList(String database, String udfMatching) {
        return null;
    }

    public List<String> getColumnList(String columnNameMatching, List<String> dbList, List<String> tblList, List<String> colList) throws HadoopException {
        return Subject.doAs(getLoginSubject(), (PrivilegedAction<List<String>>) () -> {
            List<String> ret;

            try {
                if (enableHiveMetastoreLookup) {
                    ret = getClmListFromHM(columnNameMatching, dbList, tblList, colList);
                } else {
                    ret = getClmList(columnNameMatching, dbList, tblList, colList);
                }
            } catch (HadoopException he) {
                LOG.error("<== HiveClient getColumnList() :Unable to get the Column List", he);

                throw he;
            }

            return ret;
        });
    }

    public void close() {
        Subject.doAs(getLoginSubject(), (PrivilegedAction<Void>) () -> {
            close(con);

            return null;
        });
    }

    private List<String> getDBListFromHM(String databaseMatching, List<String> dbList) throws HadoopException {
        LOG.debug("==> HiveClient getDBListFromHM databaseMatching : {} ExcludedbList : {}", databaseMatching, dbList);

        List<String> ret = new ArrayList<>();

        try {
            if (hiveClient != null) {
                List<String> hiveDBList;

                if (databaseMatching.equalsIgnoreCase("*")) {
                    hiveDBList = hiveClient.getAllDatabases();
                } else {
                    hiveDBList = hiveClient.getDatabases(databaseMatching);
                }

                if (hiveDBList != null) {
                    for (String dbName : hiveDBList) {
                        if (dbList != null && dbList.contains(dbName)) {
                            continue;
                        }

                        ret.add(dbName);
                    }
                }
            }
        } catch (TException e) {
            String          msgDesc      = "Unable to get Database";
            HadoopException hdpException = new HadoopException(msgDesc, e);

            hdpException.generateResponseDataMap(false, getMessage(e), msgDesc + ERR_MSG, null, null);

            LOG.debug("<== HiveClient.getDBListFromHM() Error : ", e);

            throw hdpException;
        }

        LOG.debug("<== HiveClient.getDBListFromHM(): {}", ret);

        return ret;
    }

    private List<String> getDBList(String databaseMatching, List<String> dbList) throws HadoopException {
        LOG.debug("==> HiveClient getDBList databaseMatching : {} ExcludedbList :{}", databaseMatching, dbList);

        List<String> ret = new ArrayList<>();

        if (con != null) {
            Statement stat = null;
            ResultSet rs   = null;
            String    sql  = "show databases";

            if (databaseMatching != null && !databaseMatching.isEmpty()) {
                sql = sql + " like \"" + databaseMatching + "\"";
            }

            try {
                stat = con.createStatement();
                rs   = stat.executeQuery(sql);

                while (rs.next()) {
                    String dbName = rs.getString(1);

                    if (dbList != null && dbList.contains(dbName)) {
                        continue;
                    }

                    ret.add(dbName);
                }
            } catch (SQLTimeoutException sqlt) {
                String          msgDesc      = "Time Out, Unable to execute SQL [" + sql + "].";
                HadoopException hdpException = new HadoopException(msgDesc, sqlt);

                hdpException.generateResponseDataMap(false, getMessage(sqlt), msgDesc + ERR_MSG, null, null);

                LOG.debug("<== HiveClient.getDBList() Error : ", sqlt);

                throw hdpException;
            } catch (SQLException sqle) {
                String          msgDesc      = "Unable to execute SQL [" + sql + "].";
                HadoopException hdpException = new HadoopException(msgDesc, sqle);

                hdpException.generateResponseDataMap(false, getMessage(sqle), msgDesc + ERR_MSG, null, null);

                LOG.debug("<== HiveClient.getDBList() Error : ", sqle);

                throw hdpException;
            } finally {
                close(rs);
                close(stat);
            }
        }

        LOG.debug("<== HiveClient.getDBList(): {}", ret);

        return ret;
    }

    private List<String> getTblListFromHM(String tableNameMatching, List<String> dbList, List<String> tblList) throws HadoopException {
        LOG.debug("==> HiveClient getTblListFromHM() tableNameMatching : {} ExcludedbList :{}ExcludeTableList :{}", tableNameMatching, dbList, tblList);

        List<String> ret = new ArrayList<>();

        if (hiveClient != null && dbList != null && !dbList.isEmpty()) {
            for (String dbName : dbList) {
                try {
                    List<String> hiveTblList = hiveClient.getTables(dbName, tableNameMatching);

                    for (String tblName : hiveTblList) {
                        if (tblList != null && tblList.contains(tblName)) {
                            continue;
                        }

                        ret.add(tblName);
                    }
                } catch (MetaException e) {
                    String          msgDesc      = "Unable to get Table.";
                    HadoopException hdpException = new HadoopException(msgDesc, e);

                    hdpException.generateResponseDataMap(false, getMessage(e), msgDesc + ERR_MSG, null, null);

                    LOG.debug("<== HiveClient.getTblListFromHM() Error : ", e);

                    throw hdpException;
                }
            }
        }

        LOG.debug("<== HiveClient getTblListFromHM() {}", ret);

        return ret;
    }

    private List<String> getTblList(String tableNameMatching, List<String> dbList, List<String> tblList) throws HadoopException {
        LOG.debug("==> HiveClient getTblList() tableNameMatching : {} ExcludedbList :{}ExcludeTableList :{}", tableNameMatching, dbList, tblList);

        List<String> ret = new ArrayList<>();

        if (con != null) {
            Statement stat = null;
            ResultSet rs   = null;
            String   sql   = null;

            try {
                if (dbList != null && !dbList.isEmpty()) {
                    for (String db : dbList) {
                        sql = "use " + db;

                        try {
                            stat = con.createStatement();

                            stat.execute(sql);
                        } finally {
                            close(stat);

                            stat = null;
                        }

                        sql = "show tables ";

                        if (tableNameMatching != null && !tableNameMatching.isEmpty()) {
                            sql = sql + " like \"" + tableNameMatching + "\"";
                        }

                        try {
                            stat = con.createStatement();
                            rs   = stat.executeQuery(sql);

                            while (rs.next()) {
                                String tblName = rs.getString(1);

                                if (tblList != null && tblList.contains(tblName)) {
                                    continue;
                                }

                                ret.add(tblName);
                            }
                        } finally {
                            close(rs);
                            close(stat);

                            rs   = null;
                            stat = null;
                        }
                    }
                }
            } catch (SQLTimeoutException sqlt) {
                String          msgDesc      = "Time Out, Unable to execute SQL [" + sql + "].";
                HadoopException hdpException = new HadoopException(msgDesc, sqlt);

                hdpException.generateResponseDataMap(false, getMessage(sqlt), msgDesc + ERR_MSG, null, null);

                LOG.debug("<== HiveClient.getTblList() Error : ", sqlt);

                throw hdpException;
            } catch (SQLException sqle) {
                String          msgDesc      = "Unable to execute SQL [" + sql + "].";
                HadoopException hdpException = new HadoopException(msgDesc, sqle);

                hdpException.generateResponseDataMap(false, getMessage(sqle), msgDesc + ERR_MSG, null, null);

                LOG.debug("<== HiveClient.getTblList() Error : ", sqle);

                throw hdpException;
            }
        }

        LOG.debug("<== HiveClient getTblList() {}", ret);

        return ret;
    }

    private List<String> getClmListFromHM(String columnNameMatching, List<String> dbList, List<String> tblList, List<String> colList) throws HadoopException {
        LOG.debug("==> HiveClient.getClmListFromHM() columnNameMatching: {} dbList :{} tblList: {} colList: {}", columnNameMatching, dbList, tblList, colList);

        List<String> ret                     = new ArrayList<>();
        String       columnNameMatchingRegEx = null;

        if (columnNameMatching != null && !columnNameMatching.isEmpty()) {
            columnNameMatchingRegEx = columnNameMatching;
        }

        if (hiveClient != null && dbList != null && !dbList.isEmpty() && tblList != null && !tblList.isEmpty()) {
            for (String db : dbList) {
                for (String tbl : tblList) {
                    try {
                        List<FieldSchema> hiveSch = hiveClient.getFields(db, tbl);

                        if (hiveSch != null) {
                            for (FieldSchema sch : hiveSch) {
                                String columnName = sch.getName();

                                if (colList != null && colList.contains(columnName)) {
                                    continue;
                                }

                                if (columnNameMatchingRegEx == null) {
                                    ret.add(columnName);
                                } else if (FilenameUtils.wildcardMatch(columnName, columnNameMatchingRegEx)) {
                                    ret.add(columnName);
                                }
                            }
                        }
                    } catch (TException e) {
                        String          msgDesc      = "Unable to get Columns.";
                        HadoopException hdpException = new HadoopException(msgDesc, e);

                        hdpException.generateResponseDataMap(false, getMessage(e), msgDesc + ERR_MSG, null, null);

                        LOG.debug("<== HiveClient.getClmListFromHM() Error : ", e);

                        throw hdpException;
                    }
                }
            }
        }

        LOG.debug("<== HiveClient.getClmListFromHM() {}", ret);

        return ret;
    }

    private List<String> getClmList(String columnNameMatching, List<String> dbList, List<String> tblList, List<String> colList) throws HadoopException {
        LOG.debug("==> HiveClient.getClmList() columnNameMatching: {} dbList :{} tblList: {} colList: {}", columnNameMatching, dbList, tblList, colList);

        List<String> ret = new ArrayList<>();

        if (con != null) {
            String columnNameMatchingRegEx = null;

            if (columnNameMatching != null && !columnNameMatching.isEmpty()) {
                columnNameMatchingRegEx = columnNameMatching;
            }

            Statement stat = null;
            ResultSet rs   = null;
            String    sql  = null;

            if (dbList != null && !dbList.isEmpty() && tblList != null && !tblList.isEmpty()) {
                for (String db : dbList) {
                    for (String tbl : tblList) {
                        try {
                            sql = "use " + db;

                            try {
                                stat = con.createStatement();

                                stat.execute(sql);
                            } finally {
                                close(stat);
                            }

                            sql  = "describe  " + tbl;
                            stat = con.createStatement();
                            rs   = stat.executeQuery(sql);

                            while (rs.next()) {
                                String columnName = rs.getString(1);

                                if (colList != null && colList.contains(columnName)) {
                                    continue;
                                }

                                if (columnNameMatchingRegEx == null) {
                                    ret.add(columnName);
                                } else if (FilenameUtils.wildcardMatch(columnName, columnNameMatchingRegEx)) {
                                    ret.add(columnName);
                                }
                            }
                        } catch (SQLTimeoutException sqlt) {
                            String          msgDesc      = "Time Out, Unable to execute SQL [" + sql + "].";
                            HadoopException hdpException = new HadoopException(msgDesc, sqlt);

                            hdpException.generateResponseDataMap(false, getMessage(sqlt), msgDesc + ERR_MSG, null, null);

                            LOG.debug("<== HiveClient.getClmList() Error : ", sqlt);

                            throw hdpException;
                        } catch (SQLException sqle) {
                            String          msgDesc      = "Unable to execute SQL [" + sql + "].";
                            HadoopException hdpException = new HadoopException(msgDesc, sqle);

                            hdpException.generateResponseDataMap(false, getMessage(sqle), msgDesc + ERR_MSG, null, null);

                            LOG.debug("<== HiveClient.getClmList() Error : ", sqle);

                            throw hdpException;
                        } finally {
                            close(rs);
                            close(stat);
                        }
                    }
                }
            }
        }

        LOG.debug("<== HiveClient.getClmList() {}", ret);

        return ret;
    }

    private void close(Statement aStat) {
        try {
            if (aStat != null) {
                aStat.close();
            }
        } catch (SQLException e) {
            LOG.error("Unable to close SQL statement", e);
        }
    }

    private void close(ResultSet aResultSet) {
        try {
            if (aResultSet != null) {
                aResultSet.close();
            }
        } catch (SQLException e) {
            LOG.error("Unable to close ResultSet", e);
        }
    }

    private void close(Connection aCon) {
        try {
            if (aCon != null) {
                aCon.close();
            }
        } catch (SQLException e) {
            LOG.error("Unable to close SQL Connection", e);
        }
    }

    private void initConnection() throws HadoopException {
        try {
            initConnection(null, null);
        } catch (HadoopException he) {
            LOG.error("Unable to Connect to Hive", he);

            throw he;
        }
    }

    private void initConnection(String userName, String password) throws HadoopException {
        if (enableHiveMetastoreLookup) {
            try {
                HiveConf conf = new HiveConf();

                if (!StringUtils.isEmpty(hiveSiteFilePath)) {
                    File f = new File(hiveSiteFilePath);

                    if (f.exists()) {
                        conf.addResource(f.toURI().toURL());
                    } else {
                        LOG.debug("Hive site conf file path {} does not exists for Hive Metastore lookup", hiveSiteFilePath);
                    }
                } else {
                    LOG.debug("Hive site conf file path property not found for Hive Metastore lookup");
                }

                hiveClient = new HiveMetaStoreClient(conf);
            } catch (HadoopException he) {
                String          msgDesc      = "initConnection: Class or its nullary constructor might not accessible. So unable to initiate connection to hive thrift server instance.";
                HadoopException hdpException = new HadoopException(msgDesc, he);

                hdpException.generateResponseDataMap(false, getMessage(he), msgDesc + ERR_MSG, null, null);

                LOG.debug(msgDesc, hdpException);

                throw hdpException;
            } catch (MalformedURLException e) {
                String          msgDesc      = "initConnection: URL might be malformed. So unable to initiate connection to hive thrift server instance.";
                HadoopException hdpException = new HadoopException(msgDesc, e);

                hdpException.generateResponseDataMap(false, getMessage(e), msgDesc + ERR_MSG, null, null);

                LOG.debug(msgDesc, hdpException);

                throw hdpException;
            } catch (MetaException e) {
                String          msgDesc      = "initConnection: Meta info is not proper. So unable to initiate connection to hive thrift server instance.";
                HadoopException hdpException = new HadoopException(msgDesc, e);

                hdpException.generateResponseDataMap(false, getMessage(e), msgDesc + ERR_MSG, null, null);

                LOG.debug(msgDesc, hdpException);

                throw hdpException;
            } catch (Throwable t) {
                String          msgDesc      = "Unable to connect to Hive Thrift Server instance";
                HadoopException hdpException = new HadoopException(msgDesc, t);

                hdpException.generateResponseDataMap(false, getMessage(t), msgDesc + ERR_MSG, null, null);

                LOG.debug(msgDesc, hdpException);

                throw hdpException;
            }
        } else {
            Properties prop            = getConfigHolder().getRangerSection();
            String     driverClassName = prop.getProperty("jdbc.driverClassName");
            String     url             = prop.getProperty("jdbc.url");

            if (driverClassName != null) {
                try {
                    Driver driver = (Driver) Class.forName(driverClassName).newInstance();

                    DriverManager.registerDriver(driver);
                } catch (SQLException e) {
                    String          msgDesc      = "initConnection: Caught SQLException while registering Hive driver, so Unable to connect to Hive Thrift Server instance.";
                    HadoopException hdpException = new HadoopException(msgDesc, e);

                    hdpException.generateResponseDataMap(false, getMessage(e), msgDesc + ERR_MSG, null, null);

                    LOG.debug(msgDesc, hdpException);

                    throw hdpException;
                } catch (IllegalAccessException ilae) {
                    String          msgDesc      = "initConnection: Class or its nullary constructor might not accessible. So unable to initiate connection to hive thrift server instance.";
                    HadoopException hdpException = new HadoopException(msgDesc, ilae);

                    hdpException.generateResponseDataMap(false, getMessage(ilae), msgDesc + ERR_MSG, null, null);

                    LOG.debug(msgDesc, hdpException);

                    throw hdpException;
                } catch (InstantiationException ie) {
                    String          msgDesc      = "initConnection: Class may not have its nullary constructor or may be the instantiation fails for some other reason. So unable to initiate connection to hive thrift server instance.";
                    HadoopException hdpException = new HadoopException(msgDesc, ie);

                    hdpException.generateResponseDataMap(false, getMessage(ie), msgDesc + ERR_MSG, null, null);

                    LOG.debug(msgDesc, hdpException);

                    throw hdpException;
                } catch (ExceptionInInitializerError eie) {
                    String          msgDesc = "initConnection: Got ExceptionInInitializerError, The initialization provoked by this method fails. So unable to initiate connection to hive thrift server instance.";
                    HadoopException hdpException = new HadoopException(msgDesc, eie);

                    hdpException.generateResponseDataMap(false, getMessage(eie), msgDesc + ERR_MSG, null, null);

                    LOG.debug(msgDesc, hdpException);

                    throw hdpException;
                } catch (SecurityException se) {
                    String msgDesc = "initConnection: unable to initiate connection to hive thrift server instance,"
                            + " The caller's class loader is not the same as or an ancestor "
                            + "of the class loader for the current class and invocation of "
                            + "s.checkPackageAccess() denies access to the package of this class.";
                    HadoopException hdpException = new HadoopException(msgDesc, se);

                    hdpException.generateResponseDataMap(false, getMessage(se), msgDesc + ERR_MSG, null, null);

                    LOG.debug(msgDesc, hdpException);

                    throw hdpException;
                } catch (Throwable t) {
                    String          msgDesc      = "initConnection: Unable to connect to Hive Thrift Server instance, please provide valid value of field : {jdbc.driverClassName}.";
                    HadoopException hdpException = new HadoopException(msgDesc, t);

                    hdpException.generateResponseDataMap(false, getMessage(t), msgDesc + ERR_MSG, null, "jdbc.driverClassName");

                    LOG.debug(msgDesc, hdpException);

                    throw hdpException;
                }
            }

            try {
                if (userName == null && password == null) {
                    con = DriverManager.getConnection(url);
                } else {
                    String decryptedPwd = null;

                    try {
                        decryptedPwd = PasswordUtils.decryptPassword(password);
                    } catch (Exception ex) {
                        LOG.info("Password decryption failed; trying Hive connection with received password string");
                    } finally {
                        if (decryptedPwd == null) {
                            decryptedPwd = password;
                        }
                    }

                    con = DriverManager.getConnection(url, userName, decryptedPwd);
                }
            } catch (SQLException | SecurityException e) {
                String          msgDesc      = "Unable to connect to Hive Thrift Server instance.";
                HadoopException hdpException = new HadoopException(msgDesc, e);

                hdpException.generateResponseDataMap(false, getMessage(e), msgDesc + ERR_MSG, null, null);

                LOG.debug(msgDesc, hdpException);

                throw hdpException;
            } catch (Throwable t) {
                String          msgDesc      = "Unable to connect to Hive Thrift Server instance";
                HadoopException hdpException = new HadoopException(msgDesc, t);

                hdpException.generateResponseDataMap(false, getMessage(t), msgDesc + ERR_MSG, null, url);

                LOG.debug(msgDesc, hdpException);

                throw hdpException;
            }
        }
    }
}
