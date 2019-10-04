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
      final SingleConnectionFactory cf = SingleConnectionFactory.builder()
        .config(ConnectionConfig.builder()
          .url("ldap://ldap-test")
          .useStartTLS(true)
          .connectTimeout(Duration.ofSeconds(60))
          .reconnectTimeout(Duration.ofSeconds(90))
          .responseTimeout(Duration.ofSeconds(60))
          .autoReconnect(true)
          .autoReconnectCondition(metadata -> {
            if (metadata.getAttempts() <= 5) {
              try {
                final Duration sleepTime = Duration.ofSeconds(3).multipliedBy(metadata.getAttempts());
                Thread.sleep(sleepTime.toMillis());
              } catch (InterruptedException ie) {}
              return true;
            }
            return false;})
          .sslConfig(SslConfig.builder().trustManagers(new AllowAnyTrustManager()).build())
          .build())
        .build();
      cf.initialize();
      SearchOperation bind = new SearchOperation(cf, "dc=vt,dc=edu");
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
