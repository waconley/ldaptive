import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.ldaptive.*;
import org.ldaptive.auth.*;
import org.ldaptive.pool.*;
import org.ldaptive.ssl.*;

public final class Ldaptive {

  private Ldaptive() {
  }

  public static void main(final String[] args)
    throws Exception
  {
    doSearch();
  }

  private static void doSearch()
  {
    try {
      SearchOperation bind = new SearchOperation(
        DefaultConnectionFactory.builder()
          .config(ConnectionConfig.builder()
            .url("ldap://ldap-test:389")
            .useStartTLS(false)
            .connectionInitializer(BindConnectionInitializer.builder()
              .dn("uid=1,ou=test,dc=vt,dc=edu")
              .credential("VKSxXwlU7YssGl1foLMH2mGMWkifbODb1djfJ4t2")
              .build())
            .build())
          .build(),
        "dc=vt,dc=edu");
      SearchResponse response = bind.execute("(uid=1)");
      System.out.println("Search #1: " + response.toString());
      System.out.println("Waiting...");
      // Wait 10 seconds for next search
      Thread.sleep(10000);
      SearchResponse response2 = bind.execute("(uupid=dhawes)");
      System.out.println("Search #2: " + response2.toString());
    } catch (Throwable e) {
      System.out.println(
        "Execution caught exception: " + e.getClass() +
          " -- " + (e.getCause() != null ? e.getCause().getClass() : "") +
          " -- " + e.getMessage());
      System.exit(1);
    }
  }
}
