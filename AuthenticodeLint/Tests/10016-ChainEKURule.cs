﻿using System.Security.Cryptography.X509Certificates;
using AuthenticodeExaminer;
using System.Security.Cryptography;

namespace AuthenticodeLint.Rules
{
    public class ChainEKURule : CertificateChainRuleBase
    {
        public override int RuleId => 10016;

        public override string RuleName => "EKU for Certificate Chain";

        public override string ShortDescription => "Checks if signing certificate has code signing as EKU or the whole chain must not have any EKU.";

        public override RuleSet RuleSet => RuleSet.All;
        
        protected override bool ValidateChain(ICmsSignature signer, X509Chain chain, SignatureLogger verboseWriter)
        {
            return ValidatEKUForChain(signer, chain, verboseWriter);
        }

        private static bool ValidatEKUForChain(ICmsSignature signature, X509Chain chain, SignatureLogger verboseWriter)
        {
            bool signingCertEKU = false;
            bool chainEKU = false;
            X509ExtensionCollection extensions = signature.Certificate.Extensions;
            foreach (X509Extension extension in extensions)
            {
                if (extension.Oid.FriendlyName == "Enhanced Key Usage")
                {
                    signingCertEKU = true;
                    //break;
                    X509EnhancedKeyUsageExtension ext = (X509EnhancedKeyUsageExtension)extension;

                    OidCollection oids = ext.EnhancedKeyUsages;
                    EKUCritical = ext.Critical;

                    foreach (Oid oid in oids)
                    {
                        //if (oid.Equals("1.3.6.1.5.5.7.3.3"))


                        EKU_oidStr = oid.FriendlyName + "(" + oid.Value + ")" + ";" + EKU_oidStr;
                    }
                    Console.WriteLine(EKU_oidStr);
                }
            }
                string EKU = 
            var signatureStrength = GetHashStrenghForComparison(signature.DigestAlgorithm.Value);
            var strongShaChain = true;
            var leafCertificateSignatureAlgorithm = chain.ChainElements[0].Certificate.SignatureAlgorithm;
            var leafCertificateSignatureAlgorithmStrength = GetHashStrenghForComparison(leafCertificateSignatureAlgorithm.Value);
            //We use count-1 because we don't want to validate the root certificate.
            for (var i = 0; i < chain.ChainElements.Count - 1; i++)
            {
                var element = chain.ChainElements[i];
                var signatureAlgorithm = element.Certificate.SignatureAlgorithm;
                var certificateHashStrength = GetHashStrenghForComparison(signatureAlgorithm.Value);
                if (certificateHashStrength < signatureStrength)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Certificate {element.Certificate.Thumbprint} in chain uses {element.Certificate.SignatureAlgorithm.FriendlyName} for its signature algorithm instead of at least {signature.DigestAlgorithm.FriendlyName}.");
                    strongShaChain = false;
                }
                //Check that all intermediates are at least as strong as the leaf.
                else if (certificateHashStrength < leafCertificateSignatureAlgorithmStrength)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Certificate {element.Certificate.Thumbprint} in chain uses {element.Certificate.SignatureAlgorithm.FriendlyName} for its signature algorithm instead of at least {signature.DigestAlgorithm.FriendlyName}.");
                }
            }
            return strongShaChain;
        }

        //Returns a value for comparison. These values are not intended to be a bit size, but only used for comparing
        //angainst other values.
        private static int GetHashStrenghForComparison(string oid)
        {
            switch (oid)
            {
                case KnownOids.MD2:
                    return 2;
                case KnownOids.MD4:
                    return 4;
                case KnownOids.MD5:
                    return 5;
                case KnownOids.SHA1:
                case KnownOids.sha1ECDSA:
                case KnownOids.sha1RSA:
                    return 10;
                case KnownOids.SHA256:
                case KnownOids.sha256ECDSA:
                case KnownOids.sha256RSA:
                    return 256;
                case KnownOids.SHA384:
                case KnownOids.sha384ECDSA:
                case KnownOids.sha384RSA:
                    return 384;
                case KnownOids.SHA512:
                case KnownOids.sha512ECDSA:
                case KnownOids.sha512RSA:
                    return 512;
                default:
                    return 0;
            }
        }
    }
}
