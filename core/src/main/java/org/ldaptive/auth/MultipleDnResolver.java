/* See LICENSE for licensing and NOTICE for copyright. */
package org.ldaptive.auth;

import java.util.Map;
import java.util.concurrent.ExecutorService;
import org.ldaptive.LdapException;

/**
 * Looks up a user's DN using multiple DN resolvers. Each DN resolver is invoked on a separate thread. Each resolved DN
 * is used by the authentication handler.
 *
 * @author  Middleware Services
 */
public class MultipleDnResolver extends AbstractMultipleDnResolver
{


  /** Default constructor. */
  public MultipleDnResolver() {}


  /**
   * Creates a new multiple dn resolver.
   *
   * @param  resolvers  dn resolvers
   */
  public MultipleDnResolver(final Map<String, DnResolver> resolvers)
  {
    super(resolvers);
  }


  /**
   * Creates a new multiple dn resolver.
   *
   * @param  resolvers  dn resolvers
   * @param  es  executor service for invoking DN resolvers
   */
  public MultipleDnResolver(final Map<String, DnResolver> resolvers, final ExecutorService es)
  {
    super(resolvers, es);
  }


  @Override
  public String resolve(final User user)
    throws LdapException
  {
    final MultiDn results = resolveDns(user);
    return results.isEmpty() ? null : results.serialize();
  }
}
