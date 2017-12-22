/*
 * @(#)CrowdAuthenticationManager.java
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

import org.acegisecurity.AccountExpiredException;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.CredentialsExpiredException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.InsufficientAuthenticationException;

import com.atlassian.crowd.exception.ApplicationPermissionException;
import com.atlassian.crowd.exception.ExpiredCredentialException;
import com.atlassian.crowd.exception.InactiveAccountException;
import com.atlassian.crowd.exception.InvalidAuthenticationException;
import com.atlassian.crowd.exception.OperationFailedException;
import com.atlassian.crowd.exception.UserNotFoundException;
import com.atlassian.crowd.model.user.User;

import hudson.security.SecurityRealm;

/**
 * This class implements the authentication manager for Jenkins.
 *
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 07.09.2011
 * @version $Id$
 */
public class CrowdAuthenticationManager implements AuthenticationManager {
  /** Used for logging purposes. */
  private static final Logger LOG = Logger.getLogger(CrowdAuthenticationManager.class.getName());

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
  public CrowdAuthenticationManager(CrowdConfigurationService pConfiguration) {
    this.configuration = pConfiguration;
  }

  /**
   * {@inheritDoc}
   *
   * @see org.acegisecurity.AuthenticationManager#authenticate(org.acegisecurity.Authentication)
   */
  @Override
  public Authentication authenticate(Authentication authentication) throws AuthenticationException {
    final String username = authentication.getPrincipal().toString();

    // checking whether there's already a SSO token
    if (null == authentication.getCredentials() && authentication instanceof CrowdAuthenticationToken
        && null != ((CrowdAuthenticationToken) authentication).getSSOToken()) {
      // SSO token available => user already authenticated
      if (CrowdAuthenticationManager.LOG.isLoggable(Level.FINER))
        CrowdAuthenticationManager.LOG.finer("User '" + username + "' already authenticated");
      return authentication;
    }

    final String password = authentication.getCredentials().toString();

    if (!this.configuration.allowedGroupNames.isEmpty())
      // ensure that the group is available, active and that the user
      // is a member of it
      if (!this.configuration.isGroupMember(username))
        throw new InsufficientAuthenticationException(
            ErrorMessages.userNotValid(username, this.configuration.allowedGroupNames));

    //String displayName = null;
    try {
      // authenticate user
      if (CrowdAuthenticationManager.LOG.isLoggable(Level.FINE))
        CrowdAuthenticationManager.LOG.fine("Authenticating user: " + username);
      final User user = this.configuration.crowdClient.authenticateUser(username, password);
      CrowdAuthenticationToken.updateUserInfo(user);
      //displayName = user.getDisplayName();
    } catch (final UserNotFoundException ex) {
      if (CrowdAuthenticationManager.LOG.isLoggable(Level.INFO))
        CrowdAuthenticationManager.LOG.info(ErrorMessages.userNotFound(username));
      throw new BadCredentialsException(ErrorMessages.userNotFound(username), ex);
    } catch (final ExpiredCredentialException ex) {
      CrowdAuthenticationManager.LOG.warning(ErrorMessages.expiredCredentials(username));
      throw new CredentialsExpiredException(ErrorMessages.expiredCredentials(username), ex);
    } catch (final InactiveAccountException ex) {
      CrowdAuthenticationManager.LOG.warning(ErrorMessages.accountExpired(username));
      throw new AccountExpiredException(ErrorMessages.accountExpired(username), ex);
    } catch (final ApplicationPermissionException ex) {
      CrowdAuthenticationManager.LOG.warning(ErrorMessages.applicationPermission());
      throw new AuthenticationServiceException(ErrorMessages.applicationPermission(), ex);
    } catch (final InvalidAuthenticationException ex) {
      CrowdAuthenticationManager.LOG.warning(ErrorMessages.invalidAuthentication());
      throw new AuthenticationServiceException(ErrorMessages.invalidAuthentication(), ex);
    } catch (final OperationFailedException ex) {
      CrowdAuthenticationManager.LOG.log(Level.SEVERE, ErrorMessages.operationFailed(), ex);
      throw new AuthenticationServiceException(ErrorMessages.operationFailed(), ex);
    }

    // user successfully authenticated
    // => retrieve the list of groups the user is a member of
    final List<GrantedAuthority> authorities = new ArrayList<>();

    // add the "authenticated" authority to the list of granted
    // authorities...
    authorities.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
    // ..and finally all authorities retrieved from the Crowd server
    authorities.addAll(this.configuration.getAuthoritiesForUser(username));

    // user successfully authenticated => create authentication token
    if (CrowdAuthenticationManager.LOG.isLoggable(Level.FINE))
      CrowdAuthenticationManager.LOG.fine("User successfully authenticated; creating authentication token");

    return new CrowdAuthenticationToken(username, password, authorities, null);
  }

}
