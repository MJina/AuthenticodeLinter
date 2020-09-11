using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AuthenticodeExaminer;


namespace AuthenticodeLinter.Tests
{
    public class CRLDistributionPointTest : IAuthenticodeSignatureTest
    {
        public int Test => 10007;

        public string TestName => "CRL Distribution Point Test";

        public string ShortDescription => "Check if signature provides CRL distribution point.";

        public TestSet TestSet => TestSet.All;

        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature);
            var pass = false;
            foreach (var signature in signatures)
            {
                string serialNumber = "";
                string crlDistPoint = "";
                Boolean crlCritical = false;

                string thumbprint = signature.Certificate.Thumbprint;
                var digestStr = HashHelpers.GetHashForSignature(signature);//message digest of siganture(signature->details->advance->msg digest)
                serialNumber = signature.Certificate.SerialNumber;
                X509ExtensionCollection extensions = signature.Certificate.Extensions;
                foreach (X509Extension extension in extensions)
                {
                    if (extension.Oid.FriendlyName == "CRL Distribution Points")
                    {
                       /* This extension MAY be present.If present, it MUST NOT be marked critical, 
                        * and it MUST contain the HTTP URL of the CA’s CRL service.*/
                        //Boolean crlHttpExists = false;
                        crlDistPoint = extension.Format(true);
                        crlCritical = extension.Critical;
                        Console.WriteLine(crlDistPoint);
                     /*   if (crlDistPoint.Contains("http://"))
                        {
                            //crlHttpExists = true;
                            Console.WriteLine("Has http crl");
                        }
                        if (crlDistPoint.Contains("ldap://"))
                        {
                            Console.WriteLine("Has ldap crl");

                        }*/
                    }
                  

                }

                if (crlDistPoint != "")
                {
                    if (crlDistPoint.Contains("http://") && !crlCritical)
                    {
                        verboseWriter.LogSignatureMessage(signature, "Signature has properly provided CRL distribution point.");
                        pass = true;
                    }
                    else
                    {
                        verboseWriter.LogSignatureMessage(signature, "Signature has not properly provided CRL distribution point.");
                        pass = false;
                    }
                }
                else
                {
                    verboseWriter.LogSignatureMessage(signature, "Signature has not provided CRL distribution point.");
                    pass = false;
                }

                }

                return pass ? TestResult.Pass : TestResult.Fail;
        }
    }
}
