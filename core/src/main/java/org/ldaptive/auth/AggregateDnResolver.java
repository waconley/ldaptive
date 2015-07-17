/* See LICENSE for licensing and NOTICE for copyright. */
package org.ldaptive.auth;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.ldaptive.LdapException;
import org.ldaptive.LdapUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Looks up a user's DN using multiple DN resolvers. Each DN resolver is invoked on a separate thread. If multiple DNs
 * are allowed then the first one retrieved is returned.
 *
 * @author  Middleware Services
 */
public class AggregateDnResolver implements DnResolver
{

  /** Logger for this class. */
  protected final Logger logger = LoggerFactory.getLogger(getClass());

  /** To submit operations to. */
  private final ExecutorService service;

  /** Labeled DN resolvers. */
  private Map<String, DnResolver> dnResolvers;

  /** Whether to throw an exception if multiple DNs are found. */
  private boolean allowMultipleDns;


  /** Default constructor. */
  public AggregateDnResolver()
  {
    service = Executors.newCachedThreadPool();
  }


  /**
   * Creates a new aggregate dn resolver.
   *
   * @param  resolvers  dn resolvers
   */
  public AggregateDnResolver(final Map<String, DnResolver> resolvers)
  {
    this(resolvers, Executors.newCachedThreadPool());
  }


  /**
   * Creates a new aggregate dn resolver.
   *
   * @param  resolvers  dn resolvers
   * @param  es  executor service for invoking DN resolvers
   */
  public AggregateDnResolver(final Map<String, DnResolver> resolvers, final ExecutorService es)
  {
    setDnResolvers(resolvers);
    service = es;
  }


  /**
   * Returns the DN resolvers to aggregate over.
   *
   * @return  map of label to dn resolver
   */
  public Map<String, DnResolver> getDnResolvers()
  {
    return Collections.unmodifiableMap(dnResolvers);
  }


  /**
   * Sets the DN resolvers to aggregate over.
   *
   * @param  resolvers  to set
   */
  public void setDnResolvers(final Map<String, DnResolver> resolvers)
  {
    logger.trace("setting dnResolvers: {}", resolvers);
    dnResolvers = resolvers;
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
   * #resolve(String)} finds that more than one DN resolver returns a DN. Otherwise the first DN found is returned.
   *
   * @param  b  whether multiple DNs are allowed
   */
  public void setAllowMultipleDns(final boolean b)
  {
    logger.trace("setting allowMultipleDns: {}", b);
    allowMultipleDns = b;
  }


  @Override
  public String resolve(final String user)
    throws LdapException
  {
    final CompletionService<String> cs = new ExecutorCompletionService<>(service);
    final List<String> results = new ArrayList<>(dnResolvers.size());
    for (final Map.Entry<String, DnResolver> entry : dnResolvers.entrySet()) {
      cs.submit(
        new Callable<String>() {
          @Override
          public String call()
            throws Exception
          {
            final String dn = entry.getValue().resolve(user);
            if (dn != null && !dn.isEmpty()) {
              return String.format("%s:%s", entry.getKey(), dn);
            }
            return null;
          }
        });
      logger.debug("submitted DN resolver {}", entry.getValue());
    }
    for (int i = 0; i < dnResolvers.size(); i++) {
      try {
        logger.debug("waiting on DN resolver #{}", i);

        final String dn = cs.take().get();
        logger.debug("resolved dn {}", dn);
        if (dn != null) {
          results.add(LdapUtils.base64Encode(dn));
        }
      } catch (ExecutionException e) {
        if (e.getCause() instanceof LdapException) {
          throw (LdapException) e.getCause();
        } else if (e.getCause() instanceof RuntimeException) {
          throw (RuntimeException) e.getCause();
        } else {
          logger.warn("ExecutionException thrown, ignoring", e);
        }
      } catch (InterruptedException e) {
        logger.warn("InterruptedException thrown, ignoring", e);
      }
    }
    if (results.isEmpty()) {
      return null;
    }
    if (results.size() > 1 && !allowMultipleDns) {
      throw new LdapException("Found more than (1) DN for: " + user);
    }
    final StringBuilder sb = new StringBuilder();
    for (String dn : results) {
      sb.append(dn).append(":");
    }
    sb.deleteCharAt(sb.length() - 1);
    return sb.toString();
  }


  /**
   * DNs are encoded in base64 format to allow for concatenation and the returning of multiple DNs in this component.
   *
   * @param  dn  returned from {@link #resolve(String)}
   *
   * @return  array of decoded DNs
   */
  public static String[] decodeDn(final String dn)
  {
    final String[] encodedDns = dn.split(":");
    final String[] decodedDns = new String[encodedDns.length];
    for (int i = 0; i < encodedDns.length; i++) {
      decodedDns[i] = LdapUtils.utf8Encode(LdapUtils.base64Decode(encodedDns[i]));
    }
    return decodedDns;
  }


  /** Invokes {@link ExecutorService#shutdown()} on the underlying executor service. */
  public void shutdown()
  {
    service.shutdown();
  }


  @Override
  protected void finalize()
    throws Throwable
  {
    try {
      shutdown();
    } finally {
      super.finalize();
    }
  }


  @Override
  public String toString()
  {
    return
      String.format(
        "[%s@%d::service=%s, dnResolvers=%s, allowMultipleDns=%s",
        getClass().getName(),
        hashCode(),
        service,
        dnResolvers,
        allowMultipleDns);
  }


  /**
   * Used in conjunction with an {@link AggregateDnResolver} to authenticate the resolved DN. In particular, the
   * resolved DN is expected to be of the form: label:DN where the label indicates the authentication handler to use.
   * This class will invoke an authentication handler for each DN, returning the first successful response.
   */
  public static class AuthenticationHandler implements org.ldaptive.auth.AuthenticationHandler
  {

    /** Logger for this class. */
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /** Labeled authentication handlers. */
    private Map<String, org.ldaptive.auth.AuthenticationHandler> authenticationHandlers;


    /** Default constructor. */
    public AuthenticationHandler() {}


    /**
     * Creates a new aggregate authentication handler.
     *
     * @param  handlers  authentication handlers
     */
    public AuthenticationHandler(final Map<String, org.ldaptive.auth.AuthenticationHandler> handlers)
    {
      setAuthenticationHandlers(handlers);
    }


    /**
     * Returns the authentication handlers to aggregate over.
     *
     * @return  map of label to authentication handler
     */
    public Map<String, org.ldaptive.auth.AuthenticationHandler> getAuthenticationHandlers()
    {
      return Collections.unmodifiableMap(authenticationHandlers);
    }


    /**
     * Sets the authentication handlers to aggregate over.
     *
     * @param  handlers  to set
     */
    public void setAuthenticationHandlers(final Map<String, org.ldaptive.auth.AuthenticationHandler> handlers)
    {
      logger.trace("setting authenticationHandlers: {}", handlers);
      authenticationHandlers = handlers;
    }


    @Override
    public AuthenticationHandlerResponse authenticate(final AuthenticationCriteria criteria)
      throws LdapException
    {
      AuthenticationHandlerResponse response = null;
      final String[] decodedDns = decodeDn(criteria.getDn());
      for (final String dn : decodedDns) {
        final String[] labeledDn = dn.split(":", 2);
        final org.ldaptive.auth.AuthenticationHandler ah = authenticationHandlers.get(labeledDn[0]);
        if (ah == null) {
          throw new LdapException("Could not find authentication handler for label: " + labeledDn[0]);
        }
        criteria.setDn(labeledDn[1]);
        response = ah.authenticate(criteria);
        logger.debug("criteria {} produced authentication handler response {}", criteria, response);
        if (response.getResult()) {
          break;
        }
      }
      return response;
    }


    @Override
    public String toString()
    {
      return
        String.format(
          "[%s@%d::authenticationHandlers=%s",
          getClass().getName(),
          hashCode(),
          authenticationHandlers);
    }
  }
}
