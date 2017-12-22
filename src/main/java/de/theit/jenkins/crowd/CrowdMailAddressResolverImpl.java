/*
 * @(#)CrowdMailAddressResolverImpl.java
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

import java.util.logging.Level;
import java.util.logging.Logger;

import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;

import hudson.Extension;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.tasks.MailAddressResolver;
import jenkins.model.Jenkins;

/**
 * This class resolves email addresses via lookup in Crowd.
 *
 * @author <a href="mailto:theit@gmx.de">Thorsten Heit (theit@gmx.de)</a>
 * @since 08.09.2011
 * @version $Id$
 */
@Extension
public class CrowdMailAddressResolverImpl extends MailAddressResolver {
  /** For logging purposes. */
  private static final Logger LOG = Logger.getLogger(CrowdMailAddressResolverImpl.class.getName());

  /**
   * {@inheritDoc}
   *
   * @see hudson.tasks.MailAddressResolver#findMailAddressFor(hudson.model.User)
   */
  @Override
  public String findMailAddressFor(User u) {
    String mail = null;
    final SecurityRealm realm = Jenkins.getInstance().getSecurityRealm();

    if (realm instanceof CrowdSecurityRealm)
      try {
        // Workaround:
        // The user object given as parameter contains the user's
        // display name. Looking up a user in Crowd by the full display
        // name doesn't work; we have to use the user's Id instead which
        // is actually appended at the end of the display name in
        // brackets
        String userId = u.getId();
        final int pos = userId.lastIndexOf('(');
        if (pos > 0) {
          final int pos2 = userId.indexOf(')', pos + 1);
          if (pos2 > pos)
            userId = userId.substring(pos + 1, pos2);
        }

        if (CrowdMailAddressResolverImpl.LOG.isLoggable(Level.FINE))
          CrowdMailAddressResolverImpl.LOG.fine("Looking up mail address for user: " + userId);
        final CrowdUser details = (CrowdUser) realm.loadUserByUsername(userId);
        mail = details.getEmailAddress();
      } catch (final UsernameNotFoundException ex) {
        if (CrowdMailAddressResolverImpl.LOG.isLoggable(Level.INFO))
          CrowdMailAddressResolverImpl.LOG.info("Failed to look up email address in Crowd");
      } catch (final DataAccessException ex) {
        CrowdMailAddressResolverImpl.LOG.log(Level.SEVERE, "Access exception trying to look up email address in Crowd",
            ex);
      }

    return mail;
  }
}
