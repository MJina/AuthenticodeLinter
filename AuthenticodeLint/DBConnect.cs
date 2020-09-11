using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using MySql.Data.MySqlClient;

namespace AuthenticodeLinter
{
   
    public class DBConnect
    {

        private static MySqlConnection connection;
        private static string server;
        private static string database;
        private static string uid;
        private static string password;
        private static Boolean disable = false;
        // SignatureLogger verboseWriter;
         SignatureLogger verboseWriter = new MemorySignatureLogger();

        //public object MessageBox { get; private set; }

        //Constructor
        static DBConnect()
        {
            Instance = new DBConnect();
            server = "localhost";
            database = "dbname";
            uid = "user";
            password = "pass";
            string connectionString;
            connectionString = "SERVER=" + server + ";" + "DATABASE=" + database + ";" + "UID=" + uid + ";" + "PASSWORD=" + password + ";";

            connection = new MySqlConnection(connectionString);
        }

        public static DBConnect Instance { get; }

        //open connection to database
#pragma warning disable CS0161 // 'DBConnect.OpenConnection()': not all code paths return a value
        private static bool OpenConnection()
#pragma warning restore CS0161 // 'DBConnect.OpenConnection()': not all code paths return a value
        {
            if(connection != null)
                CloseConnection();
            try

            {
                connection.Open();
                return true;
            }
            
            catch (MySqlException ex)
            {
                Console.Out.WriteLine(ex.Message);
               // verboseWriter.LogMessage(ex.Message);
                return false;
            }
        }

        //Close connection
        private static bool CloseConnection()
        {
            try
            {
            connection.Close();
            return true;
            }
            catch (MySqlException ex)
            {
                Console.Out.WriteLine(ex.Message);
                return false;
            }
        }

        //Insert into application table
        public static void InsertApplicationTable(String appID, String fileID, String Portal, int Signed, String FileType, int Num_exe)
        {
            if (Program.InsertApplication)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO application(appID, fileID, Portal, Signed, FileType, Num_exe) VALUES(?appID, ?fileID, ?Portal, ?Signed, ?FileType, ?Num_exe)";

                comm.Parameters.Add("?appID", MySqlDbType.String);
                comm.Parameters["?appID"].Value = appID;

                comm.Parameters.Add("?fileID", MySqlDbType.String);
                comm.Parameters["?fileID"].Value = fileID;

                comm.Parameters.Add("?Portal", MySqlDbType.String);
                comm.Parameters["?Portal"].Value = Portal;

                comm.Parameters.Add("?Signed", MySqlDbType.String);
                comm.Parameters["?Signed"].Value = Signed;

                comm.Parameters.Add("?FileType", MySqlDbType.String);
                comm.Parameters["?FileType"].Value = FileType;

                comm.Parameters.Add("?Num_exe", MySqlDbType.String);
                comm.Parameters["?Num_exe"].Value = Num_exe;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        //Insert into signaturedate table
        public static void InsertSignatureDateTable(string appID, String fileID, String signatureHash, Int32 notBeforeY, Int32 notBeforeM, Int32 notBeforeD, Int32 notAfterY, Int32 notAfterM, Int32 notAfterD, string thumbprint, int signatureIndex)
        {
            if (Program.InsertSigantureDate)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO signaturedate(appID, fileID, signatureHash, notBeforeY, notBeforeM, notBeforeD, notAfterY, notAfterM, notAfterD, thumbprint, signatureIndex) VALUES(?appID, ?fileID, ?signatureHash, ?notBeforeY, ?notBeforeM, ?notBeforeD, ?notAfterY, ?notAfterM, ?notAfterD, ?thumbprint, ?signatureIndex)";
               
                comm.Parameters.Add("?appID", MySqlDbType.String);
                comm.Parameters["?appID"].Value = appID;

                comm.Parameters.Add("?fileID", MySqlDbType.String);
                comm.Parameters["?fileID"].Value = fileID;

                comm.Parameters.Add("?signatureHash", MySqlDbType.String);
                comm.Parameters["?signatureHash"].Value = signatureHash;

                comm.Parameters.Add("?notBeforeY", MySqlDbType.Int32);
                comm.Parameters["?notBeforeY"].Value = notBeforeY;

                comm.Parameters.Add("?notBeforeM", MySqlDbType.Int32);
                comm.Parameters["?notBeforeM"].Value = notBeforeM;

                comm.Parameters.Add("?notBeforeD", MySqlDbType.Int32);
                comm.Parameters["?notBeforeD"].Value = notBeforeD;

                comm.Parameters.Add("?notAfterY", MySqlDbType.Int32);
                comm.Parameters["?notAftery"].Value = notAfterY;

                comm.Parameters.Add("?notAfterM", MySqlDbType.Int32);
                comm.Parameters["?notAfterM"].Value = notAfterM;

                comm.Parameters.Add("?notAfterD", MySqlDbType.Int32);
                comm.Parameters["?notAfterD"].Value = notAfterD;

                comm.Parameters.Add("?thumbprint", MySqlDbType.String);
                comm.Parameters["?thumbprint"].Value = thumbprint;

                comm.Parameters.Add("?signatureIndex", MySqlDbType.Int32);
                comm.Parameters["?signatureIndex"].Value = signatureIndex;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        //Insert into tssignaturedate table
        public static void InsertTSSignatureDateTable(String appID, string fileID, String signatureHash, Int32 notBeforeY, Int32 notBeforeM, Int32 notBeforeD, Int32 notAfterY, Int32 notAfterM, Int32 notAfterD, string thumbprint, int signatureIndex)
        {
            if (Program.InsertTSSigantureDate)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO tssignaturedate(appID, fileID, signatureHash, notBeforeY, notBeforeM, notBeforeD, notAfterY, notAfterM, notAfterD, thumbprint, signatureIndex) VALUES(?appID, ?fileID, ?signatureHash, ?notBeforeY, ?notBeforeM, ?notBeforeD, ?notAfterY, ?notAfterM, ?notAfterD, ?thumbprint, ?signatureIndex)";
               
                comm.Parameters.Add("?appID", MySqlDbType.String);
                comm.Parameters["?appID"].Value = appID;

                comm.Parameters.Add("?fileID", MySqlDbType.String);
                comm.Parameters["?fileID"].Value = fileID;

                comm.Parameters.Add("?signatureHash", MySqlDbType.String);
                comm.Parameters["?signatureHash"].Value = signatureHash;

                comm.Parameters.Add("?notBeforeY", MySqlDbType.Int32);
                comm.Parameters["?notBeforeY"].Value = notBeforeY;

                comm.Parameters.Add("?notBeforeM", MySqlDbType.Int32);
                comm.Parameters["?notBeforeM"].Value = notBeforeM;

                comm.Parameters.Add("?notBeforeD", MySqlDbType.Int32);
                comm.Parameters["?notBeforeD"].Value = notBeforeD;

                comm.Parameters.Add("?notAfterY", MySqlDbType.Int32);
                comm.Parameters["?notAftery"].Value = notAfterY;

                comm.Parameters.Add("?notAfterM", MySqlDbType.Int32);
                comm.Parameters["?notAfterM"].Value = notAfterM;

                comm.Parameters.Add("?notAfterD", MySqlDbType.Int32);
                comm.Parameters["?notAfterD"].Value = notAfterD;

                comm.Parameters.Add("?thumbprint", MySqlDbType.String);
                comm.Parameters["?thumbprint"].Value = thumbprint;

                comm.Parameters.Add("?signatureIndex", MySqlDbType.Int32);
                comm.Parameters["?signatureIndex"].Value = signatureIndex;

                OpenConnection();
                try
               {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        //Insert into signature table
        public static void InsertSignatureTable(String fileID, string appID, String signatureHash, String digestAlgorithm, int version, int ts, string thumbprint, string issuer, string issuerName, string subject, string subjectName, int signatureIndex)
        {
            if (Program.InsertSignature)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO signature(fileID, appID, signatureHash, digestAlgorithm, version, ts, thumbprint, issuer, issuerName, subject, subjectName, signatureIndex) VALUES(?fileID, ?appID, ?signatureHash, ?digestAlgorithm, ?version, ?ts, ?thumbprint, ?issuer, ?issuerName, ?subject, ?subjectName, ?signatureIndex)";
                comm.Parameters.Add("?fileID", MySqlDbType.String);
                comm.Parameters["?fileID"].Value = fileID;

                comm.Parameters.Add("?appID", MySqlDbType.String);
                comm.Parameters["?appID"].Value = appID;

                comm.Parameters.Add("?signatureHash", MySqlDbType.String);
                comm.Parameters["?signatureHash"].Value = signatureHash;

                comm.Parameters.Add("?digestAlgorithm", MySqlDbType.String);
                comm.Parameters["?digestAlgorithm"].Value = digestAlgorithm;

                comm.Parameters.Add("?version", MySqlDbType.Int32);
                comm.Parameters["?version"].Value = version;

                comm.Parameters.Add("?ts", MySqlDbType.Int32);
                comm.Parameters["?ts"].Value = ts;

                comm.Parameters.Add("?thumbprint", MySqlDbType.String);
                comm.Parameters["?thumbprint"].Value = thumbprint;

                comm.Parameters.Add("?issuer", MySqlDbType.String);
                comm.Parameters["?issuer"].Value = issuer;

                comm.Parameters.Add("?issuerName", MySqlDbType.String);
                comm.Parameters["?issuerName"].Value = issuerName;

                comm.Parameters.Add("?subject", MySqlDbType.String);
                comm.Parameters["?subject"].Value = subject;

                comm.Parameters.Add("?subjectName", MySqlDbType.String);
                comm.Parameters["?subjectName"].Value = subjectName;

                comm.Parameters.Add("?signatureIndex", MySqlDbType.Int32);
                comm.Parameters["?signatureIndex"].Value = signatureIndex;

                OpenConnection();
                try
               {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        //Insert into tssignature table
        public static void InsertTSSignatureTable(string appID, String fileID, String signatureHash, String digestAlgorithm, int version, int validHashAlg, string signatureThumbprint, string tsThumbprint, string issuer, string issuerName, string subject, string subjectName)
        {
            if (Program.InsertTSSiganture)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO tssignature(appID, fileID, signatureHash, digestAlgorithm, version, validHashAlg, signatureThumbprint, tsThumbprint, issuer, issuerName, subject, subjectName) VALUES(?appID, ?fileID, ?signatureHash, ?digestAlgorithm, ?version, ?validHashAlg, ?signatureThumbprint, ?tsThumbprint, ?issuer, ?issuerName, ?subject, ?subjectName)";
                
                comm.Parameters.Add("?appID", MySqlDbType.String);
                comm.Parameters["?appID"].Value = appID;

                comm.Parameters.Add("?fileID", MySqlDbType.String);
                comm.Parameters["?fileID"].Value = fileID;

                comm.Parameters.Add("?signatureHash", MySqlDbType.String);
                comm.Parameters["?signatureHash"].Value = signatureHash;

                comm.Parameters.Add("?digestAlgorithm", MySqlDbType.String);
                comm.Parameters["?digestAlgorithm"].Value = digestAlgorithm;

                comm.Parameters.Add("?version", MySqlDbType.Int32);
                comm.Parameters["?version"].Value = version;

                comm.Parameters.Add("?validHashAlg", MySqlDbType.Int32);
                comm.Parameters["?validHashAlg"].Value = validHashAlg;

                comm.Parameters.Add("?signatureThumbprint", MySqlDbType.String);
                comm.Parameters["?signatureThumbprint"].Value = signatureThumbprint;

                comm.Parameters.Add("?tsThumbprint", MySqlDbType.String);
                comm.Parameters["?tsThumbprint"].Value = tsThumbprint;

                comm.Parameters.Add("?issuer", MySqlDbType.String);
                comm.Parameters["?issuer"].Value = issuer;

                comm.Parameters.Add("?issuerName", MySqlDbType.String);
                comm.Parameters["?issuerName"].Value = issuerName;

                comm.Parameters.Add("?subject", MySqlDbType.String);
                comm.Parameters["?subject"].Value = subject;

                comm.Parameters.Add("?subjectName", MySqlDbType.String);
                comm.Parameters["?subjectName"].Value = subjectName;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

/*        public static void UpdateSignatureDateTable(string ID, string signatureHash, string tsNotBefore, string tsNotAfter)
        {
            string query = "UPDATE signature SET tsNotBefore=?tsNotBefore, tsNotAfter=?tsNotAfter WHERE ID=?ID and signatureHash=?signatureHash";
            MySqlCommand comm = connection.CreateCommand();
            comm.CommandText = query;
            comm.Parameters.Add("?ID", MySqlDbType.String);
            comm.Parameters["?ID"].Value = ID;
            comm.Parameters.Add("?signatureHash", MySqlDbType.String);
            comm.Parameters["?signatureHash"].Value = signatureHash;
            comm.Parameters.Add("?tsNotBefore", MySqlDbType.String);
            comm.Parameters["?tsNotBefore"].Value = tsNotBefore;
            comm.Parameters.Add("?tsNotAfter", MySqlDbType.String);
            comm.Parameters["?tsNotAfter"].Value = tsNotAfter;
            OpenConnection();
            try
            {
                comm.ExecuteNonQuery();
            }
            catch (MySqlException ex)
            {
                Console.Out.WriteLine(ex.Message);
            }
            CloseConnection();
        }*/


        //Insert into norevocationvalidation table
        public static void InsertValidationNoRevocationTable(String appID, string fileID, int valid, string msg_authlint)
        {
            if (Program.InsertValidation)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO validationnorevocation(appID, fileID, valid, msg_authlint) VALUES(?appID, ?fileID, ?valid, ?msg_authlint)";
               
                comm.Parameters.Add("?appID", MySqlDbType.String);
                comm.Parameters["?appID"].Value = appID;

                comm.Parameters.Add("?fileID", MySqlDbType.String);
                comm.Parameters["?fileID"].Value = fileID;

                comm.Parameters.Add("?valid", MySqlDbType.Int16);
                comm.Parameters["?valid"].Value = valid;

                comm.Parameters.Add("?msg_authlint", MySqlDbType.String);
                comm.Parameters["?msg_authlint"].Value = msg_authlint;


                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        //Insert into validationonlinerevocation table
        public static void InsertValidationOnlineRevocationTable(String appID, string fileID, int valid, string msg_authlint)
        {
            if (Program.InsertValidation)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO validationonlinerevocation(appID, fileID, valid, msg_authlint) VALUES(?appID, ?fileID, ?valid, ?msg_authlint)";

                comm.Parameters.Add("?appID", MySqlDbType.String);
                comm.Parameters["?appID"].Value = appID;

                comm.Parameters.Add("?fileID", MySqlDbType.String);
                comm.Parameters["?fileID"].Value = fileID;

                comm.Parameters.Add("?valid", MySqlDbType.Int16);
                comm.Parameters["?valid"].Value = valid;

                comm.Parameters.Add("?msg_authlint", MySqlDbType.String);
                comm.Parameters["?msg_authlint"].Value = msg_authlint;


                OpenConnection();
               try
                {
                    comm.ExecuteNonQuery();
               }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        //Insert into validationofflinerevocation table
        public static void InsertValidationOfflineRevocationTable(String appID, string fileID, int valid, string msg_authlint)
        {
            if (Program.InsertValidation)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO validationofflinerevocation(appID, fileID, valid, msg_authlint) VALUES(?appID, ?fileID, ?valid, ?msg_authlint)";

                comm.Parameters.Add("?appID", MySqlDbType.String);
                comm.Parameters["?appID"].Value = appID;

                comm.Parameters.Add("?fileID", MySqlDbType.String);
                comm.Parameters["?fileID"].Value = fileID;

                comm.Parameters.Add("?valid", MySqlDbType.Int16);
                comm.Parameters["?valid"].Value = valid;

                comm.Parameters.Add("?msg_authlint", MySqlDbType.String);
                comm.Parameters["?msg_authlint"].Value = msg_authlint;


                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }
        //Insert into rules table
        public static void InsertRulsTable(int ruleID, string name, string result, string appID, string fileID, string signatureHash, string thumbprint, string portal)
        {

            if (Program.InsertRules)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO rules(rule_ID, Name, result, App_ID, File_ID, signature_hash, thumbprint, portal) VALUES(?rule_ID, Name, ?result, ?App_ID, ?File_ID, ?signature_hash, ?thumbprint, ?portal)";

                comm.Parameters.Add("?rule_ID", MySqlDbType.Int16);
                comm.Parameters["?rule_ID"].Value = ruleID;

                comm.Parameters.Add("?Name", MySqlDbType.String);
                comm.Parameters["?Name"].Value = name;

                comm.Parameters.Add("?result", MySqlDbType.String);
                comm.Parameters["?result"].Value = result;

                comm.Parameters.Add("?App_ID", MySqlDbType.String);
                comm.Parameters["?App_ID"].Value = appID;

                comm.Parameters.Add("?File_ID", MySqlDbType.String);
                comm.Parameters["?File_ID"].Value = fileID;

                comm.Parameters.Add("?signature_hash", MySqlDbType.String);
                comm.Parameters["?signature_hash"].Value = signatureHash;

                comm.Parameters.Add("?thumbprint", MySqlDbType.String);
                comm.Parameters["?thumbprint"].Value = thumbprint;

                comm.Parameters.Add("?portal", MySqlDbType.String);
                comm.Parameters["?portal"].Value = portal;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        //Insert into extensions table
        public static void InsertExtensionsTable(string appID, String fileID, String signatureHash, String serialNumber,
            int basicConstraint_CA, int BC_pathLength, int BC_hasPathLength, string keyUsage, string subjectKeyIdentifier,
            string enhancedKeyUsages, string authorityKeyIdentifier, string certificatePolicies, string CRLDistribution, 
            int crlCritical, int EKUCritical, int KUCritical, int BCCritical, int CPCritical, int SKICritical, 
            int AKICritical, string otherExtensions, string authorityInformationAccess, int AIACritical, string thumbprint, int signatureIndex)
        {
            if (Program.InsertExtension)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO extensions(appID, fileID, signatureHash, serialNumber, basicConstraint_CA, BC_pathLength, BC_hasPathLength, keyUsage, subjectKeyIdentifier, enhancedKeyUsages, authorityKeyIdentifier, certificatePolicies, CRLDistribution, crlCritical, EKUCritical, KUCritical, BCCritical, CPCritical, SKICritical, AKICritical, otherExtensions, authorityInformationAccess, AIACritical, thumbprint, signatureIndex) VALUES(?appID, ?fileID, ?signatureHash, ?serialNumber, ?basicConstraint_CA, ?BC_pathLength, ?BC_hasPathLength, ?keyUsage, ?subjectKeyIdentifier,?enhancedKeyUsages, ?authorityKeyIdentifier, ?certificatePolicies, ?CRLDistribution, ?crlCritical, ?EKUCritical, ?KUCritical, ?BCCritical, ?CPCritical, ?SKICritical, ?AKICritical, ?otherExtensions, ?authorityInformationAccess, ?AIACritical, ?thumbprint, ?signatureIndex)";
               
                comm.Parameters.Add("?appID", MySqlDbType.String);
                comm.Parameters["?appID"].Value = appID;

                comm.Parameters.Add("?fileID", MySqlDbType.String);
                comm.Parameters["?fileID"].Value = fileID;

                comm.Parameters.Add("?signatureHash", MySqlDbType.String);
                comm.Parameters["?signatureHash"].Value = signatureHash;

                comm.Parameters.Add("?serialNumber", MySqlDbType.String);
                comm.Parameters["?serialNumber"].Value = serialNumber;

                comm.Parameters.Add("?basicConstraint_CA", MySqlDbType.Int32);
                comm.Parameters["?basicConstraint_CA"].Value = basicConstraint_CA;

                comm.Parameters.Add("?BC_pathLength", MySqlDbType.Int32);
                comm.Parameters["?BC_pathLength"].Value = BC_pathLength;

                comm.Parameters.Add("?BC_hasPathLength", MySqlDbType.Int32);
                comm.Parameters["?BC_hasPathLength"].Value = BC_hasPathLength;

                comm.Parameters.Add("?keyUsage", MySqlDbType.String);
                comm.Parameters["?keyUsage"].Value = keyUsage;

                comm.Parameters.Add("?subjectKeyIdentifier", MySqlDbType.String);
                comm.Parameters["?subjectKeyIdentifier"].Value = subjectKeyIdentifier;

                comm.Parameters.Add("?enhancedKeyUsages", MySqlDbType.String);
                comm.Parameters["?enhancedKeyUsages"].Value = enhancedKeyUsages;

                comm.Parameters.Add("?authorityKeyIdentifier", MySqlDbType.String);
                comm.Parameters["?authorityKeyIdentifier"].Value = authorityKeyIdentifier;

                comm.Parameters.Add("?certificatePolicies", MySqlDbType.String);
                comm.Parameters["?certificatePolicies"].Value = certificatePolicies;

                comm.Parameters.Add("?CRLDistribution", MySqlDbType.String);
                comm.Parameters["?CRLDistribution"].Value = CRLDistribution;

                comm.Parameters.Add("?crlCritical", MySqlDbType.Int32);
                comm.Parameters["?crlCritical"].Value = crlCritical;

                comm.Parameters.Add("?EKUCritical", MySqlDbType.Int32);
                comm.Parameters["?EKUCritical"].Value = EKUCritical;

                comm.Parameters.Add("?KUCritical", MySqlDbType.Int32);
                comm.Parameters["?KUCritical"].Value = KUCritical;

                comm.Parameters.Add("?BCCritical", MySqlDbType.Int32);
                comm.Parameters["?BCCritical"].Value = BCCritical;

                comm.Parameters.Add("?CPCritical", MySqlDbType.Int32);
                comm.Parameters["?CPCritical"].Value = CPCritical;

                comm.Parameters.Add("?SKICritical", MySqlDbType.Int32);
                comm.Parameters["?SKICritical"].Value = SKICritical;

                comm.Parameters.Add("?AKICritical", MySqlDbType.Int32);
                comm.Parameters["?AKICritical"].Value = AKICritical;

                comm.Parameters.Add("?otherExtensions", MySqlDbType.String);
                comm.Parameters["?otherExtensions"].Value = otherExtensions;

                comm.Parameters.Add("?authorityInformationAccess", MySqlDbType.String);
                comm.Parameters["?authorityInformationAccess"].Value = authorityInformationAccess;

                comm.Parameters.Add("?AIACritical", MySqlDbType.Int32);
                comm.Parameters["?AIACritical"].Value = AIACritical;

                comm.Parameters.Add("?thumbprint", MySqlDbType.String);
                comm.Parameters["?thumbprint"].Value = thumbprint;

                comm.Parameters.Add("?signatureIndex", MySqlDbType.Int32);
                comm.Parameters["?signatureIndex"].Value = signatureIndex;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }


        //Insert into tsextensions table
        public static void InsertTSExtensionsTable(string appID, String fileID, String signatureHash, String serialNumber,
            int basicConstraint_CA, int BC_pathLength, int BC_hasPathLength, string keyUsage, string subjectKeyIdentifier,
            string enhancedKeyUsages, string authorityKeyIdentifier, string certificatePolicies, string CRLDistribution,
            int crlCritical, int EKUCritical, int KUCritical, int BCCritical, int CPCritical, int SKICritical,
            int AKICritical, string otherExtensions, string authorityInformationAccess, int AIACritical, string thumbprint, int signatureIndex)
        {
            if (Program.InsertTSExtension)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO tsextensions(appID, fileID, signatureHash, serialNumber, basicConstraint_CA, BC_pathLength, BC_hasPathLength, keyUsage, subjectKeyIdentifier, enhancedKeyUsages, authorityKeyIdentifier, certificatePolicies, CRLDistribution, crlCritical, EKUCritical, KUCritical, BCCritical, CPCritical, SKICritical, AKICritical, otherExtensions, authorityInformationAccess, AIACritical, thumbprint, signatureIndex) VALUES(?appID, ?fileID, ?signatureHash, ?serialNumber, ?basicConstraint_CA, ?BC_pathLength, ?BC_hasPathLength, ?keyUsage, ?subjectKeyIdentifier,?enhancedKeyUsages, ?authorityKeyIdentifier, ?certificatePolicies, ?CRLDistribution, ?crlCritical, ?EKUCritical, ?KUCritical, ?BCCritical, ?CPCritical, ?SKICritical, ?AKICritical, ?otherExtensions, ?authorityInformationAccess, ?AIACritical, ?thumbprint, ?signatureIndex)";

                comm.Parameters.Add("?appID", MySqlDbType.String);
                comm.Parameters["?appID"].Value = appID;

                comm.Parameters.Add("?fileID", MySqlDbType.String);
                comm.Parameters["?fileID"].Value = fileID;

                comm.Parameters.Add("?signatureHash", MySqlDbType.String);
                comm.Parameters["?signatureHash"].Value = signatureHash;

                comm.Parameters.Add("?serialNumber", MySqlDbType.String);
                comm.Parameters["?serialNumber"].Value = serialNumber;

                comm.Parameters.Add("?basicConstraint_CA", MySqlDbType.Int32);
                comm.Parameters["?basicConstraint_CA"].Value = basicConstraint_CA;

                comm.Parameters.Add("?BC_pathLength", MySqlDbType.Int32);
                comm.Parameters["?BC_pathLength"].Value = BC_pathLength;

                comm.Parameters.Add("?BC_hasPathLength", MySqlDbType.Int32);
                comm.Parameters["?BC_hasPathLength"].Value = BC_hasPathLength;

                comm.Parameters.Add("?keyUsage", MySqlDbType.String);
                comm.Parameters["?keyUsage"].Value = keyUsage;

                comm.Parameters.Add("?subjectKeyIdentifier", MySqlDbType.String);
                comm.Parameters["?subjectKeyIdentifier"].Value = subjectKeyIdentifier;

                comm.Parameters.Add("?enhancedKeyUsages", MySqlDbType.String);
                comm.Parameters["?enhancedKeyUsages"].Value = enhancedKeyUsages;

                comm.Parameters.Add("?authorityKeyIdentifier", MySqlDbType.String);
                comm.Parameters["?authorityKeyIdentifier"].Value = authorityKeyIdentifier;

                comm.Parameters.Add("?certificatePolicies", MySqlDbType.String);
                comm.Parameters["?certificatePolicies"].Value = certificatePolicies;

                comm.Parameters.Add("?CRLDistribution", MySqlDbType.String);
                comm.Parameters["?CRLDistribution"].Value = CRLDistribution;

                comm.Parameters.Add("?crlCritical", MySqlDbType.Int32);
                comm.Parameters["?crlCritical"].Value = crlCritical;

                comm.Parameters.Add("?EKUCritical", MySqlDbType.Int32);
                comm.Parameters["?EKUCritical"].Value = EKUCritical;

                comm.Parameters.Add("?KUCritical", MySqlDbType.Int32);
                comm.Parameters["?KUCritical"].Value = KUCritical;

                comm.Parameters.Add("?BCCritical", MySqlDbType.Int32);
                comm.Parameters["?BCCritical"].Value = BCCritical;

                comm.Parameters.Add("?CPCritical", MySqlDbType.Int32);
                comm.Parameters["?CPCritical"].Value = CPCritical;

                comm.Parameters.Add("?SKICritical", MySqlDbType.Int32);
                comm.Parameters["?SKICritical"].Value = SKICritical;

                comm.Parameters.Add("?AKICritical", MySqlDbType.Int32);
                comm.Parameters["?AKICritical"].Value = AKICritical;

                comm.Parameters.Add("?otherExtensions", MySqlDbType.String);
                comm.Parameters["?otherExtensions"].Value = otherExtensions;

                comm.Parameters.Add("?authorityInformationAccess", MySqlDbType.String);
                comm.Parameters["?authorityInformationAccess"].Value = authorityInformationAccess;

                comm.Parameters.Add("?AIACritical", MySqlDbType.Int32);
                comm.Parameters["?AIACritical"].Value = AIACritical;

                comm.Parameters.Add("?thumbprint", MySqlDbType.String);
                comm.Parameters["?thumbprint"].Value = thumbprint;

                comm.Parameters.Add("?signatureIndex", MySqlDbType.Int32);
                comm.Parameters["?signatureIndex"].Value = signatureIndex;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        //Insert into vt table
        public static void InsertVTTable(String app_ID, String file_ID, System.DateTime scanDate, Int32 result, Int32 Vtotal, string link, string msg)
        {
            if (!disable)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO vt2(App_ID, File_ID, ScanDate, Result, VTotal, link, Msg) VALUES(?App_ID, ?File_ID, ?ScanDate, ?Result, ?VTotal, ?link, ?Msg)";
                comm.Parameters.Add("?App_ID", MySqlDbType.String);
                comm.Parameters["?App_ID"].Value = app_ID;

                comm.Parameters.Add("?File_ID", MySqlDbType.String);
                comm.Parameters["?File_ID"].Value = file_ID;

                comm.Parameters.Add("?ScanDate", MySqlDbType.DateTime);
                comm.Parameters["?ScanDate"].Value = scanDate;

                comm.Parameters.Add("?Result", MySqlDbType.Int32);
                comm.Parameters["?Result"].Value = result;

                comm.Parameters.Add("?VTotal", MySqlDbType.Int32);
                comm.Parameters["?VTotal"].Value = Vtotal;

                comm.Parameters.Add("?link", MySqlDbType.String);
                comm.Parameters["?link"].Value = link;

                comm.Parameters.Add("?Msg", MySqlDbType.String);
                comm.Parameters["?Msg"].Value = msg;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        //Insert into notvtscanned table
        public static void InsertnotvtscannedTable(String app_ID, String file_ID, string link, string msg)
        {
            if (!disable)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO notvtscanned2(App_ID, File_ID, link, Msg) VALUES(?App_ID, ?File_ID, ?link, ?Msg)";
                comm.Parameters.Add("?App_ID", MySqlDbType.String);
                comm.Parameters["?App_ID"].Value = app_ID;

                comm.Parameters.Add("?File_ID", MySqlDbType.String);
                comm.Parameters["?File_ID"].Value = file_ID;

                comm.Parameters.Add("?link", MySqlDbType.String);
                comm.Parameters["?link"].Value = link;

                comm.Parameters.Add("?Msg", MySqlDbType.String);
                comm.Parameters["?Msg"].Value = msg;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        //Insert into vtScans table
        public static void InsertVTScansTable(String engine, Int32 detected, String result, System.DateTime update, String file_ID, String App_ID, String engineVersion)
        {
            if (!disable)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO vtscans2(engine, detected, result, file_ID, App_ID, engineVersion) VALUES(?engine, ?detected, ?result, ?file_ID, ?App_ID, ?engineVersion)";
                comm.Parameters.Add("?engine", MySqlDbType.String);
                comm.Parameters["?engine"].Value = engine;

                comm.Parameters.Add("?detected", MySqlDbType.Int32);
                comm.Parameters["?detected"].Value = detected;

                comm.Parameters.Add("?result", MySqlDbType.String);
                comm.Parameters["?result"].Value = result;

                comm.Parameters.Add("?file_ID", MySqlDbType.String);
                comm.Parameters["?file_ID"].Value = file_ID;

                comm.Parameters.Add("?App_ID", MySqlDbType.String);
                comm.Parameters["?App_ID"].Value = App_ID;

                comm.Parameters.Add("?engineVersion", MySqlDbType.String);
                comm.Parameters["?engineVersion"].Value = engineVersion;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        //Insert into signtoolvalidation table
        public static void InsertSigntoolValidationTable(String app_ID, String file_ID, int verified, int signed, int error, int warning, String err, String output, int ts, int tsVerified, String thumbprint, int signatureIndex)
        {
            if (!disable)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO signtoolvalidation( appID,  fileID,  verified,  signed,  error,  warning,  err, output,  ts, tsVerified, thumbprint, signatureIndex) VALUES(?appID,  ?fileID,  ?verified,  ?signed,  ?error,  ?warning, ?err, ?output,  ?ts, ?tsVerified, ?thumbprint, ?signatureIndex)";
                comm.Parameters.Add("?appID", MySqlDbType.String);
                comm.Parameters["?appID"].Value = app_ID;

                comm.Parameters.Add("?fileID", MySqlDbType.String);
                comm.Parameters["?fileID"].Value = file_ID;

                comm.Parameters.Add("?verified", MySqlDbType.Int32);
                comm.Parameters["?verified"].Value = verified;

                comm.Parameters.Add("?signed", MySqlDbType.Int32);
                comm.Parameters["?signed"].Value = signed;

                comm.Parameters.Add("?error", MySqlDbType.Int32);
                comm.Parameters["?error"].Value = error;

                comm.Parameters.Add("?warning", MySqlDbType.Int32);
                comm.Parameters["?warning"].Value = warning;

                comm.Parameters.Add("?err", MySqlDbType.String);
                comm.Parameters["?err"].Value = err;

                comm.Parameters.Add("?output", MySqlDbType.String);
                comm.Parameters["?output"].Value = output;

                comm.Parameters.Add("?ts", MySqlDbType.Int32);
                comm.Parameters["?ts"].Value = ts;

                comm.Parameters.Add("?tsVerified", MySqlDbType.Int32);
                comm.Parameters["?tsVerified"].Value = tsVerified;

                comm.Parameters.Add("?thumbprint", MySqlDbType.String);
                comm.Parameters["?thumbprint"].Value = thumbprint;

                comm.Parameters.Add("?signatureIndex", MySqlDbType.Int32);
                comm.Parameters["?signatureIndex"].Value = signatureIndex;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        //Insert into sigcheckvalidation table
        public static void InsertSigcheckValidationTable(String app_ID, String file_ID, int verified, int signed, String err, String output)
        {
            if (!disable)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO sigcheckvalidation( appID,  fileID,  verified,  signed,  err, output) VALUES(?appID,  ?fileID,  ?verified,  ?signed, ?err, ?output)";
                comm.Parameters.Add("?appID", MySqlDbType.String);
                comm.Parameters["?appID"].Value = app_ID;

                comm.Parameters.Add("?fileID", MySqlDbType.String);
                comm.Parameters["?fileID"].Value = file_ID;

                comm.Parameters.Add("?verified", MySqlDbType.Int32);
                comm.Parameters["?verified"].Value = verified;

                comm.Parameters.Add("?signed", MySqlDbType.Int32);
                comm.Parameters["?signed"].Value = signed;

                comm.Parameters.Add("?err", MySqlDbType.String);
                comm.Parameters["?err"].Value = err;

                comm.Parameters.Add("?output", MySqlDbType.String);
                comm.Parameters["?output"].Value = output;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        //Insert into notvtscanned table
        public static void InsertPublisherTable(String app_ID, String file_ID, string link, string thumbprint, string description, string msg)
        {
            if (Program.InsertPublisher)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO publisher(App_ID, File_ID, thumbprint, link, description, Msg) VALUES(?App_ID, ?File_ID, ?thumbprint, ?link, ?description, ?Msg)";
                comm.Parameters.Add("?App_ID", MySqlDbType.String);
                comm.Parameters["?App_ID"].Value = app_ID;

                comm.Parameters.Add("?File_ID", MySqlDbType.String);
                comm.Parameters["?File_ID"].Value = file_ID;

                comm.Parameters.Add("?thumbprint", MySqlDbType.String);
                comm.Parameters["?thumbprint"].Value = thumbprint;

                comm.Parameters.Add("?link", MySqlDbType.String);
                comm.Parameters["?link"].Value = link;

                comm.Parameters.Add("?description", MySqlDbType.String);
                comm.Parameters["?description"].Value = description;

                comm.Parameters.Add("?Msg", MySqlDbType.String);
                comm.Parameters["?Msg"].Value = msg;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        public static void InsertRepeatedExtensionsTable(string app_ID, string file_ID, string repeatedExtension, string thumbprint)
        {
            if (Program.InsertRepeatedExtensions)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO repeatedExtension(App_ID, File_ID, thumbprint, repeatedExtension) VALUES(?App_ID, ?File_ID, ?thumbprint, ?repeatedExtension)";
                comm.Parameters.Add("?App_ID", MySqlDbType.String);
                comm.Parameters["?App_ID"].Value = app_ID;

                comm.Parameters.Add("?File_ID", MySqlDbType.String);
                comm.Parameters["?File_ID"].Value = file_ID;

                comm.Parameters.Add("?thumbprint", MySqlDbType.String);
                comm.Parameters["?thumbprint"].Value = thumbprint;

                comm.Parameters.Add("?repeatedExtension", MySqlDbType.String);
                comm.Parameters["?repeatedExtension"].Value = repeatedExtension;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        public static void InsertPublicKeyInfo(string app_ID, string file_ID, string signatureAlgorithm, int keySize, string thumbprint, string errMsg, int signatureIndex)
        {
            if (Program.InsertPublicKeyInfo)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO publickeyinfo(App_ID, File_ID, signatureAlgorithm, keySize, thumbprint, errMsg, signatureIndex ) VALUES(?App_ID, ?File_ID, ?signatureAlgorithm, ?keySize, ?thumbprint, ?errMsg, ?signatureIndex)";
                comm.Parameters.Add("?App_ID", MySqlDbType.String);
                comm.Parameters["?App_ID"].Value = app_ID;

                comm.Parameters.Add("?File_ID", MySqlDbType.String);
                comm.Parameters["?File_ID"].Value = file_ID;

                comm.Parameters.Add("?signatureAlgorithm", MySqlDbType.String);
                comm.Parameters["?signatureAlgorithm"].Value = signatureAlgorithm;

                comm.Parameters.Add("?keySize", MySqlDbType.Int32);
                comm.Parameters["?keySize"].Value = keySize;

                comm.Parameters.Add("?thumbprint", MySqlDbType.String);
                comm.Parameters["?thumbprint"].Value = thumbprint;

                comm.Parameters.Add("?errMsg", MySqlDbType.String);
                comm.Parameters["?errMsg"].Value = errMsg;

                comm.Parameters.Add("?signatureIndex", MySqlDbType.Int32);
                comm.Parameters["?signatureIndex"].Value = signatureIndex;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

        public static void InsertBCRepeatedExtensionsTable(string app_ID, string file_ID, int BC_extension, string thumbprint, int critical, int BC_CA, int hasPathLength, int pathLength,int chain)
        {
            if (Program.InsertBCRepeatedExtensions)
            {
                MySqlCommand comm = connection.CreateCommand();
                comm.CommandText = "INSERT INTO bcrepeatedextensions(App_ID, File_ID, extensionNum, thumbprint, critical, BC_CA, hasPathLength, pathLength, chain) VALUES(?App_ID, ?File_ID, ?extensionNum, ?thumbprint, ?critical, ?BC_CA, ?hasPathLength, ?pathLength, ?chain)";
                comm.Parameters.Add("?App_ID", MySqlDbType.String);
                comm.Parameters["?App_ID"].Value = app_ID;

                comm.Parameters.Add("?File_ID", MySqlDbType.String);
                comm.Parameters["?File_ID"].Value = file_ID;

                comm.Parameters.Add("?extensionNum", MySqlDbType.Int32);
                comm.Parameters["?extensionNum"].Value = BC_extension;

                comm.Parameters.Add("?thumbprint", MySqlDbType.String);
                comm.Parameters["?thumbprint"].Value = thumbprint;

                comm.Parameters.Add("?critical", MySqlDbType.Int32);
                comm.Parameters["?critical"].Value = critical;

                comm.Parameters.Add("?BC_CA", MySqlDbType.Int32);
                comm.Parameters["?BC_CA"].Value = BC_CA;

                comm.Parameters.Add("?hasPathLength", MySqlDbType.Int32);
                comm.Parameters["?hasPathLength"].Value = hasPathLength;

                comm.Parameters.Add("?pathLength", MySqlDbType.Int32);
                comm.Parameters["?pathLength"].Value = pathLength;

                comm.Parameters.Add("?chain", MySqlDbType.Int32);
                comm.Parameters["?chain"].Value = chain;

                OpenConnection();
                try
                {
                    comm.ExecuteNonQuery();
                }
                catch (MySqlException ex)
                {
                    Console.Out.WriteLine(ex.Message);
                }
                CloseConnection();
            }
        }

    }

}
