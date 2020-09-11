using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using AuthenticodeExaminer;


namespace AuthenticodeLinter.Tests
{
    public class TimestampedTest1 : IAuthenticodeSignatureTest
    {
        public int Test => 10003;

        public string TestName => "Timestamped Signature";

        public string ShortDescription => "Check if signatures have a timestamp counter signer.";

        public TestSet TestSet => TestSet.All;

        public TestResult Validate(IReadOnlyList<ICmsSignature> graph, SignatureLogger verboseWriter, CheckConfiguration configuration)
        {
            var signatures = graph.VisitAll(SignatureKind.AnySignature);
            var pass = true;
            int signatureIndex = 0;
            foreach (var signature in signatures)
            {
                string repeatedExtension = "";
                var counterSignatures = signature.VisitAll(SignatureKind.AnyCounterSignature).ToList();
                int ts = counterSignatures.Count;
                var isSigned = false;
                var strongSign = 0;
                var tsDigestString = "";
                string otherExtensions = "";
                string serialNumber = "";
                int pathLength = 0;
                Boolean BC_CA = false;
                Boolean hasPathLength = false;
                string KU = "";
                Boolean KUCritical = false;
                string SKI = "";
                string EKU_oidStr = "";
                string AKI = "";
                string certificatePolicies = "";
                string crlDistPoint = "";
                string authorityInformationAccess = "";
                Boolean crlCritical = false;
                Boolean EKUCritical = false;
                Boolean BCCritical = false;
                Boolean CPCritical = false;
                Boolean SKICritical = false;
                Boolean AKICritical = false;
                Boolean AIACritical = false;
               // Boolean CS_EKU = false;
                int KU_extension = 0;
                int EKU_extension = 0;
                int BC_extension = 0;
                int SKI_extension = 0;
                int AKI_extension = 0;
                int crl_extension = 0;
                int CP_extension = 0;
                int AIA_extension = 0;



                string thumbprint = signature.Certificate.Thumbprint;
                var digestStr = HashHelpers.GetHashForSignature(signature);//message digest of siganture(signature->details->advance->msg digest)
                DBConnect.InsertSignatureTable(Program.fileName, Program.appName, digestStr, signature.DigestAlgorithm.FriendlyName, signature.Certificate.Version, ts, thumbprint, signature.Certificate.Issuer, signature.Certificate.IssuerName.Name, signature.Certificate.Subject, signature.Certificate.SubjectName.Name, signatureIndex);
                System.DateTime notBeforeDate = signature.Certificate.NotBefore;
                System.DateTime notAfterDate = signature.Certificate.NotAfter;
                serialNumber = signature.Certificate.SerialNumber;
                DBConnect.InsertSignatureDateTable(Program.appName, Program.fileName, digestStr, notBeforeDate.Year, notBeforeDate.Month, notBeforeDate.Day, notAfterDate.Year, notAfterDate.Month, notAfterDate.Day, thumbprint, signatureIndex);
                X509ExtensionCollection extensions = signature.Certificate.Extensions;
                foreach (X509Extension extension in extensions)
                {
                    //extension.Oid.FriendlyName
                    Console.WriteLine(extension.Oid.FriendlyName + "(" + extension.Oid.Value + ")");


                    if (extension.Oid.FriendlyName == "Key Usage")
                    {
                        X509KeyUsageExtension ext = (X509KeyUsageExtension)extension;
                        KUCritical = ext.Critical;
                        if (KU_extension != 0)
                            repeatedExtension += extension.Oid.FriendlyName + ",";
                        KU = ext.KeyUsages.ToString();
                        Console.WriteLine(KU);
                        KU_extension++;
                    }

                    else if (extension.Oid.FriendlyName == "Basic Constraints")
                    {
                        X509BasicConstraintsExtension ext = (X509BasicConstraintsExtension)extension;
                        BCCritical = ext.Critical;
                        if(BC_extension != 0)
                            repeatedExtension += extension.Oid.FriendlyName + ",";
                        BC_CA = ext.CertificateAuthority;
                        hasPathLength = ext.HasPathLengthConstraint;
                        pathLength = ext.PathLengthConstraint;
                        Console.WriteLine(BC_CA);
                        Console.WriteLine(hasPathLength);
                        Console.WriteLine(pathLength);
                        BC_extension++;
                    }

                    else if (extension.Oid.FriendlyName == "Subject Key Identifier")
                    {
                        X509SubjectKeyIdentifierExtension ext = (X509SubjectKeyIdentifierExtension)extension;
                        SKICritical = ext.Critical;
                        if(SKI_extension != 0)
                            repeatedExtension += extension.Oid.FriendlyName + ",";
                        SKI = ext.SubjectKeyIdentifier.ToString();
                        Console.WriteLine(SKI);
                        SKI_extension++;
                    }

                    else if (extension.Oid.FriendlyName == "Authority Key Identifier")
                    {
                        AKICritical = extension.Critical;
                        if(AKI_extension != 0)
                            repeatedExtension += extension.Oid.FriendlyName + ",";
                        AKI = extension.Format(true);
                        Console.WriteLine(AKI);
                        AKI_extension++;
                    }

                    else if (extension.Oid.FriendlyName == "Enhanced Key Usage")
                    {
                        if (EKU_extension != 0)
                            repeatedExtension += extension.Oid.FriendlyName + ",";
                        X509EnhancedKeyUsageExtension ext = (X509EnhancedKeyUsageExtension)extension;
                       
                        OidCollection oids = ext.EnhancedKeyUsages;
                        EKUCritical = ext.Critical;

                        foreach (Oid oid in oids)
                        {
                            //if (oid.Equals("1.3.6.1.5.5.7.3.3"))
                           

                            EKU_oidStr = oid.FriendlyName + "(" + oid.Value + ")" + ";" + EKU_oidStr;
                        }
                        Console.WriteLine(EKU_oidStr);
                        EKU_extension++;
                    }
                    else if (extension.Oid.FriendlyName == "CRL Distribution Points")
                    {
                        /*This extension MUST be present, MUST NOT be marked critical, 
                         * and MUST contain the HTTP URL of the CA’s CRL service*/
                        //Boolean crlHttpExists = false;
                        if(crl_extension!=0)
                            repeatedExtension += extension.Oid.FriendlyName + ",";
                        crlDistPoint = extension.Format(true);
                        crlCritical = extension.Critical;
                        Console.WriteLine(crlDistPoint);
                        if (crlDistPoint.Contains("http://"))
                        {
                            //crlHttpExists = true;
                            Console.WriteLine("has http crl");
                        }
                        if (crlDistPoint.Contains("ldap://"))
                        {
                            Console.WriteLine("has ldap crl");

                        }
                        crl_extension++;
                    }
                    else if (extension.Oid.FriendlyName == "Certificate Policies")
                    {
                        if(CP_extension !=0)
                            repeatedExtension += extension.Oid.FriendlyName + ",";
                        certificatePolicies = extension.Format(true);
                        CPCritical = extension.Critical;
                        Console.WriteLine(certificatePolicies);
                        CP_extension++;
                    }

                    else if (extension.Oid.FriendlyName == "Authority Information Access")
                    {
                        if (AIA_extension != 0)
                            repeatedExtension += extension.Oid.FriendlyName + ",";
                        authorityInformationAccess = extension.Format(true);
                        AIACritical = extension.Critical;
                        Console.WriteLine(authorityInformationAccess);
                        AIA_extension++;
                    }

                    else
                    {
                        otherExtensions += ";" + extension.Oid.FriendlyName + "(" + extension.Oid.Value.ToString() + ")";

                    }

                }
                DBConnect.InsertRepeatedExtensionsTable(Program.appName, Program.fileName, repeatedExtension, thumbprint);
                DBConnect.InsertExtensionsTable(Program.appName, Program.fileName, digestStr, serialNumber, Convert.ToInt32(BC_CA), pathLength, Convert.ToInt32(hasPathLength), KU, SKI, EKU_oidStr, AKI, certificatePolicies, crlDistPoint, Convert.ToInt32(crlCritical), Convert.ToInt32(EKUCritical), Convert.ToInt32(KUCritical), Convert.ToInt32(BCCritical), Convert.ToInt32(CPCritical), Convert.ToInt32(SKICritical), Convert.ToInt32(AKICritical), otherExtensions, authorityInformationAccess, Convert.ToInt32(AIACritical), thumbprint, signatureIndex);
                Validation.validateWithSignTool(Program.filePath, signatureIndex, thumbprint);
                int tssignatureIndex = 0;
                foreach (var counterSignature in counterSignatures)
                {
                    //reset extensions' values
                     otherExtensions = "";
                     serialNumber = "";
                     pathLength = 0;
                     BC_CA = false;
                     hasPathLength = false;
                     KU = "";
                     KUCritical = false;
                     SKI = "";
                     EKU_oidStr = "";
                     AKI = "";
                     certificatePolicies = "";
                     crlDistPoint = "";
                     authorityInformationAccess = "";
                     crlCritical = false;
                     EKUCritical = false;
                     BCCritical = false;
                     CPCritical = false;
                     SKICritical = false;
                     AKICritical = false;
                     AIACritical = false;

                    tsDigestString = HashHelpers.GetHashForSignature(counterSignature);//message digest of siganture(signature->details->advance->msg digest)
                    System.DateTime tsNotBeforeDate = counterSignature.Certificate.NotBefore;
                    System.DateTime tsNotAfterDate = counterSignature.Certificate.NotAfter;

                    DBConnect.InsertTSSignatureDateTable(Program.appName, Program.fileName, tsDigestString, tsNotBeforeDate.Year, tsNotBeforeDate.Month, tsNotBeforeDate.Day, tsNotAfterDate.Year, tsNotAfterDate.Month, tsNotAfterDate.Day, counterSignature.Certificate.Thumbprint, tssignatureIndex);
                    isSigned = true;
                    if (counterSignature.DigestAlgorithm.Value == signature.DigestAlgorithm.Value)
                    {
                        strongSign++;
                        DBConnect.InsertTSSignatureTable(Program.appName, Program.fileName, tsDigestString, counterSignature.DigestAlgorithm.FriendlyName, counterSignature.Certificate.Version, 1, thumbprint, counterSignature.Certificate.Thumbprint, counterSignature.Certificate.Issuer, counterSignature.Certificate.IssuerName.Name, counterSignature.Certificate.Subject, counterSignature.Certificate.SubjectName.Name);

                    }
                    else
                        DBConnect.InsertTSSignatureTable(Program.appName, Program.fileName, tsDigestString, counterSignature.DigestAlgorithm.FriendlyName, counterSignature.Certificate.Version, 0, thumbprint, counterSignature.Certificate.Thumbprint, counterSignature.Certificate.Issuer, counterSignature.Certificate.IssuerName.Name, counterSignature.Certificate.Subject, counterSignature.Certificate.SubjectName.Name);


                    //extracting extensions of timestamp certificate

                    X509ExtensionCollection tsEextensions = signature.Certificate.Extensions;
                    foreach (X509Extension extension in tsEextensions)
                    {
                        //extension.Oid.FriendlyName
                        Console.WriteLine(extension.Oid.FriendlyName + "(" + extension.Oid.Value + ")");


                        if (extension.Oid.FriendlyName == "Key Usage")
                        {
                            X509KeyUsageExtension ext = (X509KeyUsageExtension)extension;
                            KUCritical = ext.Critical;
                            KU = ext.KeyUsages.ToString();
                            Console.WriteLine(KU);
                        }

                        else if (extension.Oid.FriendlyName == "Basic Constraints")
                        {
                            X509BasicConstraintsExtension ext = (X509BasicConstraintsExtension)extension;
                            BCCritical = ext.Critical;
                            BC_CA = ext.CertificateAuthority;
                            hasPathLength = ext.HasPathLengthConstraint;
                            pathLength = ext.PathLengthConstraint;
                            Console.WriteLine(BC_CA);
                            Console.WriteLine(hasPathLength);
                            Console.WriteLine(pathLength);
                        }

                        else if (extension.Oid.FriendlyName == "Subject Key Identifier")
                        {
                            X509SubjectKeyIdentifierExtension ext = (X509SubjectKeyIdentifierExtension)extension;
                            SKICritical = ext.Critical;
                            SKI = ext.SubjectKeyIdentifier.ToString();
                            Console.WriteLine(SKI);
                        }

                        else if (extension.Oid.FriendlyName == "Authority Key Identifier")
                        {
                            AKICritical = extension.Critical;
                            AKI = extension.Format(true);
                            Console.WriteLine(AKI);
                        }

                        else if (extension.Oid.FriendlyName == "Enhanced Key Usage")
                        {
                            //Boolean CS_EKU;
                            X509EnhancedKeyUsageExtension ext = (X509EnhancedKeyUsageExtension)extension;
                            OidCollection oids = ext.EnhancedKeyUsages;
                            EKUCritical = ext.Critical;

                            foreach (Oid oid in oids)
                            {
                                //if (oid.Equals("1.3.6.1.5.5.7.3.3"))
                                //  CS_EKU = true;
                                EKU_oidStr = oid.FriendlyName + "(" + oid.Value + ")" + ";" + EKU_oidStr;
                            }
                            Console.WriteLine(EKU_oidStr);
                        }
                        else if (extension.Oid.FriendlyName == "CRL Distribution Points")
                        {
                            /*This extension MUST be present, MUST NOT be marked critical, 
                             * and MUST contain the HTTP URL of the CA’s CRL service*/
                            //Boolean crlHttpExists = false;
                            crlDistPoint = extension.Format(true);
                            crlCritical = extension.Critical;
                            Console.WriteLine(crlDistPoint);
                            if (crlDistPoint.Contains("http://"))
                            {
                                //crlHttpExists = true;
                                Console.WriteLine("has http crl");
                            }
                            if (crlDistPoint.Contains("ldap://"))
                            {
                                Console.WriteLine("has ldap crl");

                            }
                        }
                        else if (extension.Oid.FriendlyName == "Certificate Policies")
                        {
                            certificatePolicies = extension.Format(true);
                            CPCritical = extension.Critical;
                            Console.WriteLine(certificatePolicies);
                        }

                        else if (extension.Oid.FriendlyName == "Authority Information Access")
                        {
                            authorityInformationAccess = extension.Format(true);
                            AIACritical = extension.Critical;
                            Console.WriteLine(authorityInformationAccess);
                        }

                        else
                        {
                            otherExtensions += ";" + extension.Oid.FriendlyName + "(" + extension.Oid.Value.ToString() + ")";

                        }

                    }
                    DBConnect.InsertTSExtensionsTable(Program.appName, Program.fileName, digestStr, serialNumber, Convert.ToInt32(BC_CA), pathLength, Convert.ToInt32(hasPathLength), KU, SKI, EKU_oidStr, AKI, certificatePolicies, crlDistPoint, Convert.ToInt32(crlCritical), Convert.ToInt32(EKUCritical), Convert.ToInt32(KUCritical), Convert.ToInt32(BCCritical), Convert.ToInt32(CPCritical), Convert.ToInt32(SKICritical), Convert.ToInt32(AKICritical), otherExtensions, authorityInformationAccess, Convert.ToInt32(AIACritical), thumbprint, tssignatureIndex);
                    tssignatureIndex++;

                }

                if (!isSigned && strongSign >= 1)
                {
                    throw new InvalidOperationException("Unexpectedly have a strong signature.");
                }
                if (!isSigned)
                {
                    verboseWriter.LogSignatureMessage(signature, "Signature is not timestamped.");
                    pass = false;
                }
                else if (strongSign == 0)
                {
                    verboseWriter.LogSignatureMessage(signature, $"Signature is not timestamped with the expected hash algorithm {signature.DigestAlgorithm.FriendlyName}.");
                    pass = false;
                }
                signatureIndex++;
            }

            return pass ? TestResult.Pass : TestResult.Fail;
        }
    }
}
