/*
 * @(#)CrowdConfigurationService.java
 *
 * The MIT License
 *
 * Copyright (C)2011 Thorsten Heit.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package de.theit.jenkins.crowd;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.GroupNotFoundException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.integration.http.CrowdHttpAuthenticator;
import com.atlassian.crowd.integration.http.util.CrowdHttpTokenHelper;
import com.atlassian.crowd.model.group.Group;
import com.atlassian.crowd.service.client.ClientProperties;
import com.atlassian.crowd.service.client.CrowdClient;

/**
 * This class contains all objects that are necessary to access the REST
 * services on the remote Crowd server. Additionally it contains some helper
 * methods to check for group membership and availability.
 *
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 08.09.2011
 * @version $Id$
 */
public class CrowdConfigurationService {
  /** Used for logging purposes. */
  private static final Logger LOG = Logger.getLogger(CrowdConfigurationService.class.getName());

  /**
   * The maximum number of groups that can be fetched from the Crowd server
   * for a user in one request.
   */
  private static final int MAX_GROUPS = 500;

  static public Properties getProperties(String url, String applicationName, String password,
      int sessionValidationInterval, boolean useSSO, String cookieDomain, String cookieTokenkey, Boolean useProxy,
      String httpProxyHost, String httpProxyPort, String httpProxyUsername, String httpProxyPassword,
      String socketTimeout, String httpTimeout, String httpMaxConnections) {
    // for https://docs.atlassian.com/crowd/2.7.1/com/atlassian/crowd/service/client/ClientPropertiesImpl.html
    final Properties props = new Properties();

    String crowdUrl = url;
    if (!crowdUrl.endsWith("/"))
      crowdUrl += "/";
    props.setProperty("application.name", applicationName);
    props.setProperty("application.password", password);
    props.setProperty("crowd.base.url", crowdUrl);
    props.setProperty("application.login.url", crowdUrl + "console/");
    props.setProperty("crowd.server.url", crowdUrl + "services/");
    props.setProperty("session.validationinterval", String.valueOf(sessionValidationInterval));
    //TODO move other values to jenkins web configuration
    props.setProperty("session.isauthenticated", "session.isauthenticated");
    props.setProperty("session.tokenkey", "session.tokenkey");
    props.setProperty("session.lastvalidation", "session.lastvalidation");

    if (useSSO) {
      if (cookieDomain != null && !cookieDomain.equals(""))
        props.setProperty("cookie.domain", cookieDomain);
      if (cookieTokenkey != null && !cookieTokenkey.equals(""))
        props.setProperty("cookie.tokenkey", cookieTokenkey);
    }

    if (useProxy != null && useProxy) {
      if (httpProxyHost != null && !httpProxyHost.equals(""))
        props.setProperty("http.proxy.host", httpProxyHost);
      if (httpProxyPort != null && !httpProxyPort.equals(""))
        props.setProperty("http.proxy.port", httpProxyPort);
      if (httpProxyUsername != null && !httpProxyUsername.equals(""))
        props.setProperty("http.proxy.username", httpProxyUsername);
      if (httpProxyPassword != null && !httpProxyPassword.equals(""))
        props.setProperty("http.proxy.password", httpProxyPassword);
    }

    if (socketTimeout != null && !socketTimeout.equals(""))
      props.setProperty("socket.timeout", socketTimeout);
    if (httpMaxConnections != null && !httpMaxConnections.equals(""))
      props.setProperty("http.max.connections", httpMaxConnections);
    if (httpTimeout != null && !httpTimeout.equals(""))
      props.setProperty("http.timeout", httpTimeout);

    return props;
  }

  /** The names of all user groups that are allowed to login. */
  ArrayList<String> allowedGroupNames;

  /** Holds the Crowd client properties. */
  ClientProperties clientProperties;

  /** The Crowd client to access the REST services on the remote Crowd server. */
  CrowdClient crowdClient;

  /**
   * The interface used to manage HTTP authentication and web/SSO
   * authentication integration.
   */
  CrowdHttpAuthenticator crowdHttpAuthenticator;

  /** Specifies whether nested groups may be used. */
  private final boolean nestedGroups;

  /** The helper class for Crowd SSO token operations. */
  CrowdHttpTokenHelper tokenHelper;

  public boolean useSSO;

  /**
   * Creates a new Crowd configuration object.
   *
   * @param pGroupNames
   *            The group names to use when authenticating Crowd users. May
   *            not be <code>null</code>.
   * @param pNestedGroups
   *            Specifies whether nested groups should be used when validating
   *            users against a group name.
   */
  public CrowdConfigurationService(String pGroupNames, boolean pNestedGroups) {
    if (CrowdConfigurationService.LOG.isLoggable(Level.INFO))
      CrowdConfigurationService.LOG.info("Groups given for Crowd configuration service: " + pGroupNames);
    this.allowedGroupNames = new ArrayList<>();
    for (final String group : pGroupNames.split(","))
      if (null != group && group.trim().length() > 0) {
        if (CrowdConfigurationService.LOG.isLoggable(Level.FINE))
          CrowdConfigurationService.LOG.fine("-> adding allowed group name: " + group);
        this.allowedGroupNames.add(group);
      }

    this.nestedGroups = pNestedGroups;
  }

  /**
   * Retrieves the list of all (nested) groups from the Crowd server that the
   * user is a member of.
   *
   * @param username
   *            The name of the user. May not be <code>null</code>.
   * @return The list of all groups that the user is a member of. Always
   *         non-null.
   */
  public Collection<GrantedAuthority> getAuthoritiesForUser(String username) {
    final Collection<GrantedAuthority> authorities = new TreeSet<>(
        (ga1, ga2) -> ga1.getAuthority().compareTo(ga2.getAuthority()));

    final HashSet<String> groupNames = new HashSet<>();

    // retrieve the names of all groups the user is a direct member of
    try {
      int index = 0;
      if (CrowdConfigurationService.LOG.isLoggable(Level.FINE))
        CrowdConfigurationService.LOG
            .fine("Retrieve list of groups with direct membership for user '" + username + "'...");
      while (true) {
        if (CrowdConfigurationService.LOG.isLoggable(Level.FINEST))
          CrowdConfigurationService.LOG.finest(
              "Fetching groups [" + index + "..." + (index + CrowdConfigurationService.MAX_GROUPS - 1) + "]...");
        final List<Group> groups = this.crowdClient.getGroupsForUser(username, index,
            CrowdConfigurationService.MAX_GROUPS);
        if (null == groups || groups.isEmpty())
          break;
        for (final Group group : groups)
          if (group.isActive())
            groupNames.add(group.getName());
        index += CrowdConfigurationService.MAX_GROUPS;
      }
    } catch (final UserNotFoundException ex) {
      if (CrowdConfigurationService.LOG.isLoggable(Level.INFO))
        CrowdConfigurationService.LOG.info(ErrorMessages.userNotFound(username));
    } catch (final InvalidAuthenticationException ex) {
      CrowdConfigurationService.LOG.warning(ErrorMessages.invalidAuthentication());
    } catch (final ApplicationPermissionException ex) {
      CrowdConfigurationService.LOG.warning(ErrorMessages.applicationPermission());
    } catch (final OperationFailedException ex) {
      CrowdConfigurationService.LOG.log(Level.SEVERE, ErrorMessages.operationFailed(), ex);
    }

    // now the same but for nested group membership if this configuration
    // setting is active/enabled
    if (this.nestedGroups)
      try {
        int index = 0;
        if (CrowdConfigurationService.LOG.isLoggable(Level.FINE))
          CrowdConfigurationService.LOG
              .fine("Retrieve list of groups with direct membership for user '" + username + "'...");
        while (true) {
          if (CrowdConfigurationService.LOG.isLoggable(Level.FINEST))
            CrowdConfigurationService.LOG.finest(
                "Fetching groups [" + index + "..." + (index + CrowdConfigurationService.MAX_GROUPS - 1) + "]...");
          final List<Group> groups = this.crowdClient.getGroupsForNestedUser(username, index,
              CrowdConfigurationService.MAX_GROUPS);
          if (null == groups || groups.isEmpty())
            break;
          for (final Group group : groups)
            if (group.isActive())
              groupNames.add(group.getName());
          index += CrowdConfigurationService.MAX_GROUPS;
        }
      } catch (final UserNotFoundException ex) {
        if (CrowdConfigurationService.LOG.isLoggable(Level.INFO))
          CrowdConfigurationService.LOG.info(ErrorMessages.userNotFound(username));
      } catch (final InvalidAuthenticationException ex) {
        CrowdConfigurationService.LOG.warning(ErrorMessages.invalidAuthentication());
      } catch (final ApplicationPermissionException ex) {
        CrowdConfigurationService.LOG.warning(ErrorMessages.applicationPermission());
      } catch (final OperationFailedException ex) {
        CrowdConfigurationService.LOG.log(Level.SEVERE, ErrorMessages.operationFailed(), ex);
      }

    // now create the list of authorities
    for (final String str : groupNames)
      authorities.add(new GrantedAuthorityImpl(str));

    return authorities;
  }

  /**
   * Checks if the specified group name exists on the remote Crowd server and
   * is active.
   *
   * @param groupName
   *            The name of the group to check. May not be <code>null</code>
   *            or empty.
   * @return <code>true</code> if and only if the group name is not empty,
   *         does exist on the remote Crowd server and is active.
   *         <code>false</code> else.
   * @throws InvalidAuthenticationException
   *             If the application and password are not valid.
   * @throws ApplicationPermissionException
   *             If the application is not permitted to perform the requested
   *             operation on the server
   * @throws OperationFailedException
   *             If the operation has failed for any other reason, including
   *             invalid arguments and the operation not being supported on
   *             the server.
   */
  public boolean isGroupActive(String groupName)
      throws InvalidAuthenticationException, ApplicationPermissionException, OperationFailedException {
    boolean retval = false;

    try {
      if (CrowdConfigurationService.LOG.isLoggable(Level.FINE))
        CrowdConfigurationService.LOG.fine("Checking whether group is active: " + groupName);
      final Group group = this.crowdClient.getGroup(groupName);
      if (null != group)
        retval = group.isActive();
    } catch (final GroupNotFoundException ex) {
      if (CrowdConfigurationService.LOG.isLoggable(Level.FINE))
        CrowdConfigurationService.LOG.fine(ErrorMessages.groupNotFound(groupName));
    }

    return retval;
  }

  /**
   * Checks whether the user is a member of one of the Crowd groups whose
   * members are allowed to login.
   *
   * @param username
   *            The name of the user to check. May not be <code>null</code> or
   *            empty.
   * @return <code>true</code> if and only if the group exists, is active and
   *         the user is either a direct group member or, if nested groups may
   *         be used, a nested group member. <code>false</code> else.
   */
  public boolean isGroupMember(String username) {
    boolean retval = false;

    try {
      for (final String group : this.allowedGroupNames) {
        retval = this.isGroupMember(username, group);
        if (retval)
          break;
      }
    } catch (final ApplicationPermissionException ex) {
      CrowdConfigurationService.LOG.warning(ErrorMessages.applicationPermission());
    } catch (final InvalidAuthenticationException ex) {
      CrowdConfigurationService.LOG.warning(ErrorMessages.invalidAuthentication());
    } catch (final OperationFailedException ex) {
      CrowdConfigurationService.LOG.log(Level.SEVERE, ErrorMessages.operationFailed(), ex);
    }

    return retval;
  }

  /**
   * Checks whether the user is a member of the given Crowd group.
   *
   * @param username
   *            The name of the user to check. May not be <code>null</code> or
   *            empty.
   * @param group
   *            The name of the group to check the user against. May not be
   *            <code>null</code>.
   * @return <code>true</code> if and only if the group exists, is active and
   *         the user is either a direct group member or, if nested groups may
   *         be used, a nested group member. <code>false</code> else.
   *
   * @throws ApplicationPermissionException
   *             If the application is not permitted to perform the requested
   *             operation on the server.
   * @throws InvalidAuthenticationException
   *             If the application and password are not valid.
   * @throws OperationFailedException
   *             If the operation has failed for any other reason, including
   *             invalid arguments and the operation not being supported on
   *             the server.
   */
  private boolean isGroupMember(String username, String group)
      throws ApplicationPermissionException, InvalidAuthenticationException, OperationFailedException {
    boolean retval = false;

    if (this.isGroupActive(group)) {
      if (CrowdConfigurationService.LOG.isLoggable(Level.FINE))
        CrowdConfigurationService.LOG
            .fine("Checking group membership for user '" + username + "' and group '" + group + "'...");
      if (this.crowdClient.isUserDirectGroupMember(username, group)) {
        retval = true;
        if (CrowdConfigurationService.LOG.isLoggable(Level.FINER))
          CrowdConfigurationService.LOG.finer("=> user is a direct group member");
      } else if (this.nestedGroups && this.crowdClient.isUserNestedGroupMember(username, group)) {
        retval = true;
        if (CrowdConfigurationService.LOG.isLoggable(Level.FINER))
          CrowdConfigurationService.LOG.finer("=> user is a nested group member");
      }
    }

    return retval;
  }
}
