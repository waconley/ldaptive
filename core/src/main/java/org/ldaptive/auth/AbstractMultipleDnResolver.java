/* See LICENSE for licensing and NOTICE for copyright. */
package org.ldaptive.auth;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletionService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.SearchResult;
import org.ldaptive.io.LdifReader;
import org.ldaptive.io.LdifWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Looks up a user's DN using multiple DN resolvers. Each DN resolver is invoked on a separate thread. Each resolved DN
 * is used by the authentication handler.
 *
 * @author  Middleware Services
 */
public abstract class AbstractMultipleDnResolver implements DnResolver
{

  /** Logger for this class. */
  protected final Logger logger = LoggerFactory.getLogger(getClass());

  /** To submit operations to. */
  private final ExecutorService service;

  /** Labeled DN resolvers. */
  private Map<String, DnResolver> dnResolvers;


  /** Default constructor. */
  public AbstractMultipleDnResolver()
  {
    service = Executors.newCachedThreadPool();
  }


  /**
   * Creates a new aggregate dn resolver.
   *
   * @param  resolvers  dn resolvers
   */
  public AbstractMultipleDnResolver(final Map<String, DnResolver> resolvers)
  {
    this(resolvers, Executors.newCachedThreadPool());
  }


  /**
   * Creates a new aggregate dn resolver.
   *
   * @param  resolvers  dn resolvers
   * @param  es  executor service for invoking DN resolvers
   */
  public AbstractMultipleDnResolver(final Map<String, DnResolver> resolvers, final ExecutorService es)
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
   * Uses a {@link CompletionService} to invoke each DN resolver. Collects the results in a multi dn.
   *
   * @param  user  to resolve DN for
   *
   * @return  multi dn containing one or more labeled DNs
   *
   * @throws  LdapException  if any of the DN resolvers throws
   */
  protected MultiDn resolveDns(final User user)
    throws LdapException
  {
    final MultiDn results = new MultiDn(dnResolvers.size());
    final CompletionService<String> cs = new ExecutorCompletionService<>(service);
    for (final Map.Entry<String, DnResolver> entry : dnResolvers.entrySet()) {
      cs.submit(
        () -> {
          final String dn = entry.getValue().resolve(user);
          logger.debug("DN resolver {} resolved dn {} for user {}", entry.getValue(), dn, user);
          if (dn != null && !dn.isEmpty()) {
            results.addEntry(entry.getKey(), dn);
          }
          return null;
        });
      logger.debug("submitted DN resolver {}", entry.getValue());
    }
    for (int i = 1; i <= dnResolvers.size(); i++) {
      try {
        logger.trace("waiting on DN resolver {} of {}", i, dnResolvers.size());
        cs.take().get();
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
    logger.debug("resolved DNs {}", results);
    return results;
  }


  /**
   * Creates an aggregate entry resolver using the labels from the DN resolver and the supplied entry resolver.
   *
   * @param  resolver  used for every label
   *
   * @return  aggregate entry resolver
   */
  public EntryResolver createEntryResolver(final org.ldaptive.auth.EntryResolver resolver)
  {
    final Map<String, org.ldaptive.auth.EntryResolver> resolvers = new HashMap<>(dnResolvers.size());
    for (String label : dnResolvers.keySet()) {
      resolvers.put(label, resolver);
    }
    return new EntryResolver(resolvers);
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


  /**
   * Used in conjunction with an {@link AggregateDnResolver} to authenticate the resolved DN. In particular, the
   * resolved DN is expected to be of the form: label:DN where the label indicates the authentication handler to use.
   * This class only invokes one authentication handler that matches the label found on the DN.
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
     * Creates a new abstract authentication handler.
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


    /**
     * Returns the response of the first successful authentication handler or the last failed authentication handler.
     * This method will modify the supplied criteria to the authenticated DN if multiple DNs are attempting
     * authentication.
     *
     * @param  criteria  to perform the authentication with
     *
     * @return  authentication handler response or null
     *
     * @throws LdapException
     */
    @Override
    public AuthenticationHandlerResponse authenticate(final AuthenticationCriteria criteria)
      throws LdapException
    {
      AuthenticationHandlerResponse response = null;
      final MultiDn results = MultiDn.deserialize(criteria.getDn());
      for (Map.Entry<String, String> entry : results.entries()) {
        final org.ldaptive.auth.AuthenticationHandler ah = getAuthenticationHandlers().get(entry.getKey());
        if (ah == null) {
          throw new LdapException("Could not find authentication handler for label: " + entry.getKey());
        }
        response = ah.authenticate(new AuthenticationCriteria(entry.getValue(), criteria.getAuthenticationRequest()));
        if (response.getResult()) {
          if (results.size() > 1) {
            // multiple DNs were resolved, update the criteria with the one that successfully authenticated
            // downstream components can then expect a single DN
            final MultiDn authenticatedDn = new MultiDn(entry.getKey(), entry.getValue());
            criteria.setDn(authenticatedDn.serialize());
          }
          return response;
        }
      }
      return response;
    }
  }


  /**
   * Used in conjunction with an {@link AggregateDnResolver} to resolve an entry. In particular, the resolved DN is
   * expected to be of the form: label:DN where the label indicates the entry resolver to use. This class only invokes
   * one entry resolver that matches the label found on the DN.
   */
  public static class EntryResolver implements org.ldaptive.auth.EntryResolver
  {

    /** Logger for this class. */
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /** Labeled entry resolvers. */
    private Map<String, org.ldaptive.auth.EntryResolver> entryResolvers;


    /** Default constructor. */
    public EntryResolver() {}


    /**
     * Creates a new aggregate entry resolver.
     *
     * @param  resolvers  entry resolvers
     */
    public EntryResolver(final Map<String, org.ldaptive.auth.EntryResolver> resolvers)
    {
      setEntryResolvers(resolvers);
    }


    /**
     * Returns the entry resolvers to aggregate over.
     *
     * @return  map of label to entry resolver
     */
    public Map<String, org.ldaptive.auth.EntryResolver> getEntryResolvers()
    {
      return Collections.unmodifiableMap(entryResolvers);
    }


    /**
     * Sets the entry resolvers to aggregate over.
     *
     * @param  resolvers  to set
     */
    public void setEntryResolvers(final Map<String, org.ldaptive.auth.EntryResolver> resolvers)
    {
      logger.trace("setting entryResolvers: {}", resolvers);
      entryResolvers = resolvers;
    }


    @Override
    public LdapEntry resolve(final AuthenticationCriteria criteria, final AuthenticationHandlerResponse response)
      throws LdapException
    {
      final MultiDn result = MultiDn.deserialize(criteria.getDn());
      final Map.Entry<String, String> labeledDn = result.firstEntry();
      final org.ldaptive.auth.EntryResolver er = getEntryResolvers().get(labeledDn.getKey());
      if (er == null) {
        throw new LdapException("Could not find entry resolver for label: " + labeledDn.getKey());
      }
      return er.resolve(
        new AuthenticationCriteria(labeledDn.getValue(), criteria.getAuthenticationRequest()), response);
    }
  }


  /**
   * Used in conjunction with an {@link AggregateDnResolver} to execute a list of response handlers. In particular, the
   * resolved DN is expected to be of the form: label:DN where the label indicates the response handler to use. This
   * class only invokes the response handlers that matches the label found on the DN.
   */
  public static class AuthenticationResponseHandler implements org.ldaptive.auth.AuthenticationResponseHandler
  {

    /** Logger for this class. */
    protected final Logger logger = LoggerFactory.getLogger(getClass());

    /** Labeled entry resolvers. */
    private Map<String, org.ldaptive.auth.AuthenticationResponseHandler[]> responseHandlers;


    /** Default constructor. */
    public AuthenticationResponseHandler() {}


    /**
     * Creates a new aggregate authentication response handler.
     *
     * @param  handlers  authentication response handlers
     */
    public AuthenticationResponseHandler(
      final Map<String, org.ldaptive.auth.AuthenticationResponseHandler[]> handlers)
    {
      setAuthenticationResponseHandlers(handlers);
    }


    /**
     * Returns the response handlers to aggregate over.
     *
     * @return  map of label to response handlers
     */
    public Map<String, org.ldaptive.auth.AuthenticationResponseHandler[]> getAuthenticationResponseHandlers()
    {
      return Collections.unmodifiableMap(responseHandlers);
    }


    /**
     * Sets the response handlers to aggregate over.
     *
     * @param  handlers  to set
     */
    public void setAuthenticationResponseHandlers(
      final Map<String, org.ldaptive.auth.AuthenticationResponseHandler[]> handlers)
    {
      logger.trace("setting authenticationResponseHandlers: {}", handlers);
      responseHandlers = handlers;
    }


    @Override
    public void handle(final AuthenticationResponse response) throws LdapException
    {
      final MultiDn result = MultiDn.deserialize(response.getResolvedDn());
      final Map.Entry<String, String> labeledDn = result.firstEntry();
      final org.ldaptive.auth.AuthenticationResponseHandler[] handlers =
        getAuthenticationResponseHandlers().get(labeledDn.getKey());
      if (handlers == null) {
        throw new LdapException("Could not find response handlers for label: " + labeledDn.getKey());
      }
      if (handlers.length > 0) {
        for (org.ldaptive.auth.AuthenticationResponseHandler ah : handlers) {
          ah.handle(response);
        }
      }
    }
  }


  /**
   * Class that encapsulates a map of label to DN.
   */
  protected static class MultiDn
  {

    /** Map of label to DN. */
    private final Map<String, String> labeledDns;


    /**
     * Default constructor.
     */
    public MultiDn()
    {
      labeledDns = new LinkedHashMap<>();
    }


    /**
     * Creates a new multi dn.
     *
     * @param  size  of the underlying map
     */
    public MultiDn(final int size)
    {
      labeledDns = new LinkedHashMap<>(size);
    }


    /**
     * Creates a new multi dn of size 1.
     *
     * @param  label  associated with the DN
     * @param  dn  of the user
     */
    public MultiDn(final String label, final String dn)
    {
      labeledDns = new LinkedHashMap<>(1);
      addEntry(label, dn);
    }


    /**
     * Adds the supplied label and DN.
     *
     * @param  label  associated with the DN
     * @param  dn  of the user
     */
    public void addEntry(final String label, final String dn)
    {
      labeledDns.put(label, dn);
    }


    /**
     * Returns all the entries in this multi dn.
     *
     * @return  labeled DNs
     */
    public Set<Map.Entry<String, String>> entries()
    {
      return labeledDns.entrySet();
    }


    /**
     * Returns the first entry in this multi dn.
     *
     * @return  labeled DN
     */
    public Map.Entry<String, String> firstEntry()
    {
      return labeledDns.entrySet().iterator().next();
    }


    /**
     * Returns whether this multi dn is empty.
     *
     * @return  whether this multi dn is empty
     */
    public boolean isEmpty()
    {
      return labeledDns.isEmpty();
    }


    /**
     * Returns the number of entries in this multi dn.
     *
     * @return  number of entries in this multi dn
     */
    public int size()
    {
      return labeledDns.size();
    }


    /**
     * Returns a string representation of this multi dn.
     *
     * @return  LDIF of this multi dn
     */
    public String serialize()
    {
      final SearchResult result = new SearchResult();
      for (Map.Entry<String, String> entry : labeledDns.entrySet()) {
        result.addEntry(new LdapEntry(entry.getValue(), new LdapAttribute("label", entry.getKey())));
      }
      final StringWriter writer = new StringWriter();
      final LdifWriter ldifWriter = new LdifWriter(writer);
      try {
        ldifWriter.write(result);
      } catch (IOException e) {
        throw new IllegalStateException("Could not write LDIF to String", e);
      }
      return writer.toString();
    }


    /**
     * Converts the supplied string to a multi dn.
     *
     * @param  s  LDIF that is a multi dn
     *
     * @return  multi dn
     */
    public static MultiDn deserialize(final String s)
    {
      final MultiDn multiDn = new MultiDn();
      final StringReader reader = new StringReader(s);
      final LdifReader ldifReader = new LdifReader(reader);
      try {
        final SearchResult result = ldifReader.read();
        for (LdapEntry entry : result.getEntries()) {
          multiDn.addEntry(entry.getAttribute("label").getStringValue(), entry.getDn());
        }
      } catch (IOException e) {
        throw new IllegalStateException("Could not read LDIF from String", e);
      }
      return multiDn;
    }
  }
}
