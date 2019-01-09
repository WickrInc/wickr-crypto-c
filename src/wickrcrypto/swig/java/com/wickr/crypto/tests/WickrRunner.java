package com.wickr.crypto.tests;

import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

public class WickrRunner {
  public static void main(String[] args) {
    Result result = JUnitCore.runClasses(CryptoTests.class, DevInfoTests.class, KeyStoreTests.class, NodeTests.class, IdentityTests.class, ContextTests.class, ECDHCipherTests.class, FingerprintTests.class);

    System.out.println("Completed " + 
    					result.getRunCount() + 
    					" tests in " + result.getRunTime() + "ms" +
    					 " with " + result.getFailureCount() + " failures\n");

    if (result.getFailureCount() > 0) {
      System.out.println("******* Failures ********");

      for (Failure failure : result.getFailures()) {
        System.out.println("Failure Reason: " + failure.getDescription().toString());
        System.out.println("Stack Trace:" + failure.getTrace());
      }
    }
    else {
      System.out.println("******* ALL TESTS PASSED! ********");
    }

    // Exit with non 0 status if any tests failed so that CI fails
    System.exit(result.getFailureCount());
    
  }
}
