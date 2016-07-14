/* See LICENSE for licensing and NOTICE for copyright. */
package org.ldaptive.auth;

import java.util.Map;
import java.util.concurrent.ExecutorService;
import org.ldaptive.LdapException;

/**
 * Looks up a user's DN using multiple DN resolvers. Each DN resolver is invoked on a separate thread. If multiple DNs
 * are allowed then the first one retrieved is returned.
 *
 * @author  Middleware Services
 */
public class AggregateDnResolver extends AbstractMultipleDnResolver
{

  /** Whether to throw an exception if multiple DNs are found. */
  private boolean allowMultipleDns;


  /** Default constructor. */
  public AggregateDnResolver() {}


  /**
   * Creates a new aggregate dn resolver.
   *
   * @param  resolvers  dn resolvers
   */
  public AggregateDnResolver(final Map<String, DnResolver> resolvers)
  {
    super(resolvers);
  }


  /**
   * Creates a new aggregate dn resolver.
   *
   * @param  resolvers  dn resolvers
   * @param  es  executor service for invoking DN resolvers
   */
  public AggregateDnResolver(final Map<String, DnResolver> resolvers, final ExecutorService es)
  {
    super(resolvers, es);
  }


  /**
   * Returns whether DN resolution should fail if multiple DNs are found.
   *
   * @return  whether an exception will be thrown if multiple DNs are found
   */
  public boolean getAllowMultipleDns()
  {
    return allowMultipleDns;
  }


  /**
   * Sets whether DN resolution should fail if multiple DNs are found If false an exception will be thrown if {@link
   * #resolve(User)} finds that more than one DN resolver returns a DN. Otherwise the first DN found is returned.
   *
   * @param  b  whether multiple DNs are allowed
   */
  public void setAllowMultipleDns(final boolean b)
  {
    logger.trace("setting allowMultipleDns: {}", b);
    allowMultipleDns = b;
  }


  @Override
  public String resolve(final User user)
    throws LdapException
  {
    final MultiDn results = resolveDns(user);
    if (results.isEmpty()) {
      return null;
    } else if (results.size() > 1 && !allowMultipleDns) {
      throw new LdapException("Found more than (1) DN for: " + user);
    }
    return results.serialize();
  }
}
