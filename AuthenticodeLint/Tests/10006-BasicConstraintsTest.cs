using System.Security.Cryptography.X509Certificates;
using AuthenticodeExaminer;
using System;

namespace AuthenticodeLinter.Tests
{
    public class BasicConstraintsTest : CertificateChainTest
    {
        public override int Test => 10006;

        public override string TestName => "Basic Constraints Test";

        public override string ShortDescription => "Checks if the CA filed of Basic Constraints is set to false for leaf certificate.";

        public override TestSet TestSet => TestSet.All;

      //  public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        protected override bool ValidateChain(ICmsSignature signer, X509Chain chain, SignatureLogger verboseWriter)
        {
            return ValidateChain(signer, chain, verboseWriter);
        }

        private static TestResult ValidateBasicConstraints(ICmsSignature signature, X509Chain chain, SignatureLogger verboseWriter)
        {
            var pass = false;
            Boolean BCCritical = false;
            int BC_extension = 0;
            Boolean BC_CA = false;
            Boolean hasPathLength = false;
            string KU = "";
            int pathLength = 0;
            string issuer = "";
            var leafCertificateSignatureAlgorithm = chain.ChainElements[0].Certificate.SignatureAlgorithm;
            //We use count-1 because we don't want to validate the root certificate.
            for (var i = 0; i < chain.ChainElements.Count - 1; i++)
            {
                var element = chain.ChainElements[i];
                var signatureAlgorithm = element.Certificate.SignatureAlgorithm;
                issuer = element.Certificate.Issuer;
                X509ExtensionCollection extensions = element.Certificate.Extensions;
                BC_extension = 0;
                BC_CA = false;
                hasPathLength = false;
                pathLength = 0;
                KU = "";

                foreach (X509Extension extension in extensions)
                {
                    if (extension.Oid.FriendlyName == "Basic Constraints")
                    {
                        X509BasicConstraintsExtension ext = (X509BasicConstraintsExtension)extension;
                        BCCritical = ext.Critical;
                        
                        BC_extension++;
                        BC_CA = ext.CertificateAuthority;
                        hasPathLength = ext.HasPathLengthConstraint;
                        pathLength = ext.PathLengthConstraint;

                    }
                }

                /*   if (BC_extension == 0 && i>0)
                   {
                          Console.WriteLine(issuer);
                          Console.WriteLine("No BC.");
                          Console.WriteLine(KU);
                          Console.WriteLine(Program.appName);
                          Console.WriteLine("==================================================================");
                   }*/
                if (i == 0)
                {
                    if (BC_extension == 1 && !BC_CA)
                    {
                        pass = true;
                    }
                    else if (BC_extension > 1)
                    {
                        verboseWriter.LogSignatureMessage(signature, $"Signature has duplicate Basic Constraints extension.");
                        pass = false;
                    }
                    else if (BC_extension == 1 && BC_CA)
                    {
                        verboseWriter.LogSignatureMessage(signature, $"Signature has violating CA filed for Basic Constraints.");
                        pass = false;

                    }
                    else
                        pass = false;
                }
                else
                    verboseWriter.LogSignatureMessage(signature, $"Not a leaf certificate.");
            }
            return pass ? TestResult.Pass : TestResult.Fail;
        }

    }
}
