package org.bouncycastle.crypto.agreement.test;

import junit.extensions.TestSetup;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.test.PrintTestResult;

public class AllTests
    extends TestCase
{
    public static void main(String[] args)
    {
       PrintTestResult.printResult( junit.textui.TestRunner.run(suite()));
    }

    public static Test suite()
    {
        TestSuite suite = new TestSuite("JPAKE Engine Tests");

        suite.addTestSuite(JPAKEParticipantTest.class);
        suite.addTestSuite(JPAKEPrimeOrderGroupTest.class);
        suite.addTestSuite(JPAKEUtilTest.class);

        suite.addTestSuite(ECJPAKEParticipantTest.class);
        suite.addTestSuite(ECJPAKECurveTest.class);
        suite.addTestSuite(ECJPAKEUtilTest.class);

        return new BCTestSetup(suite);
    }

    static class BCTestSetup
        extends TestSetup
    {
        public BCTestSetup(Test test)
        {
            super(test);
        }

        protected void setUp()
        {

        }

        protected void tearDown()
        {

        }
    }
}
