/*
 * @(#)CrowdUserDetailsService.java
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
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;

import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.model.user.User;

import hudson.security.SecurityRealm;

/**
 * This class provides the service to load a user object from the remote Crowd
 * server.
 *
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 07.09.2011
 * @version $Id$
 */
public class CrowdUserDetailsService implements UserDetailsService {
  /** Used for logging purposes. */
  private static final Logger LOG = Logger.getLogger(CrowdUserDetailsService.class.getName());

  /**
   * The configuration data necessary for accessing the services on the remote
   * Crowd server.
   */
  private final CrowdConfigurationService configuration;

  /**
   * Creates a new instance of this class.
   *
   * @param pConfiguration
   *            The configuration to access the services on the remote Crowd
   *            server. May not be <code>null</code>.
   */
  public CrowdUserDetailsService(CrowdConfigurationService pConfiguration) {
    this.configuration = pConfiguration;
  }

  /**
   * {@inheritDoc}
   *
   * @see org.acegisecurity.userdetails.UserDetailsService#loadUserByUsername(java.lang.String)
   */
  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {

    if (!this.configuration.allowedGroupNames.isEmpty())
      // check whether there's at least one active group the user is a member
      // of
      if (!this.configuration.isGroupMember(username))
        throw new DataRetrievalFailureException(
            ErrorMessages.userNotValid(username, this.configuration.allowedGroupNames));
    User user;
    try {
      // load the user object from the remote Crowd server
      if (CrowdUserDetailsService.LOG.isLoggable(Level.FINE))
        CrowdUserDetailsService.LOG.fine("Loading user object from the remote Crowd server...");
      user = this.configuration.crowdClient.getUser(username);
    } catch (final UserNotFoundException ex) {
      if (CrowdUserDetailsService.LOG.isLoggable(Level.INFO))
        CrowdUserDetailsService.LOG.info(ErrorMessages.userNotFound(username));
      throw new UsernameNotFoundException(ErrorMessages.userNotFound(username), ex);
    } catch (final ApplicationPermissionException ex) {
      CrowdUserDetailsService.LOG.warning(ErrorMessages.applicationPermission());
      throw new DataRetrievalFailureException(ErrorMessages.applicationPermission(), ex);
    } catch (final InvalidAuthenticationException ex) {
      CrowdUserDetailsService.LOG.warning(ErrorMessages.invalidAuthentication());
      throw new DataRetrievalFailureException(ErrorMessages.invalidAuthentication(), ex);
    } catch (final OperationFailedException ex) {
      CrowdUserDetailsService.LOG.log(Level.SEVERE, ErrorMessages.operationFailed(), ex);
      throw new DataRetrievalFailureException(ErrorMessages.operationFailed(), ex);
    }

    // create the list of granted authorities
    final List<GrantedAuthority> authorities = new ArrayList<>();
    // add the "authenticated" authority to the list of granted
    // authorities...
    authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
    // ..and all authorities retrieved from the Crowd server
    authorities.addAll(this.configuration.getAuthoritiesForUser(username));

    return new CrowdUser(user, authorities);
  }
}
