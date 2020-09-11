using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using MySql.Data.MySqlClient;
using VirusTotalNet;
using VirusTotalNet.Exceptions;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;
using VirusTotalNet.Objects;
//using VirusTotalNet.Tests.TestInternals;

namespace AuthenticodeLinter
{

    public class VTChecker
    {
        public static async Task GetScanReportForFile()
        {

            VirusTotal virusTotal = new VirusTotal("");
            //Use HTTPS instead of HTTP
            virusTotal.UseTLS = true;
            virusTotal.Timeout = TimeSpan.FromSeconds(500);

            try
            {
                FileReport fileReport = await virusTotal.GetFileReportAsync(Program.fileName);

                bool hasFileBeenScannedBefore = fileReport.ResponseCode == FileReportResponseCode.Present;
                if (!hasFileBeenScannedBefore)

                    Console.WriteLine("File has been scanned before: " + (hasFileBeenScannedBefore ? "Yes" : "No"));

                //If the file has been scanned before, the results are embedded inside the report.
                if (hasFileBeenScannedBefore)
                {
                    PrintScan(fileReport);
                }
                else
                {   
                        if (!File.Exists(Program.filePath))
                        {
                            throw new FileNotFoundException("The file was not found.", Program.filePath);
                        }

                        Stream fs = File.OpenRead(Program.filePath);
                        ScanResult fileResult = await virusTotal.ScanFileAsync(fs, Program.fileName);
                        PrintScan(fileResult);
                }
            }
            catch(VirusTotalNet.Exceptions.SizeLimitException)
            {
                
                try
                {
                    virusTotal.RestrictSizeLimits = false;
                    
                    Stream fs = File.OpenRead(Program.filePath);
                    ScanResult fileResult = await virusTotal.ScanLargeFileAsync(fs, Program.fileName);
                }
                catch (VirusTotalNet.Exceptions.SizeLimitException)
                {
                    Console.WriteLine("VirusTotalNet.Exceptions.SizeLimitException");
                    DBConnect.InsertnotvtscannedTable(Program.appName, Program.fileName, "", "SizeLimitException");
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    DBConnect.InsertnotvtscannedTable(Program.appName, Program.fileName, "", ex.Message);

                }
            }
            catch(VirusTotalNet.Exceptions.RateLimitException)
            {
                Console.WriteLine("VirusTotalNet.Exceptions.RateLimitException");
                DBConnect.InsertnotvtscannedTable(Program.appName, Program.fileName, "", "RateLimitException");
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                DBConnect.InsertnotvtscannedTable(Program.appName, Program.fileName, "", ex.Message);

            }

        }

        private static void PrintScan(FileReport fileReport)
        {
            //throw new NotImplementedException();
            Console.WriteLine("File: " + fileReport.Resource);
            Console.WriteLine("Message: " + fileReport.VerboseMsg);
            DBConnect.InsertVTTable(Program.appName, Program.fileName, fileReport.ScanDate, fileReport.Positives, fileReport.Total, fileReport.Permalink, fileReport.VerboseMsg);
            Dictionary<string, ScanEngine> engines = fileReport.scans;
            foreach (KeyValuePair<string, ScanEngine> scan in fileReport.scans)
                DBConnect.InsertVTScansTable(scan.Key, Convert.ToInt32(scan.Value.Detected), scan.Value.Result, scan.Value.Update, Program.fileName, Program.appName, scan.Value.Version);
        }

        private static void PrintScan(ScanResult scanResult)
        {
            Console.WriteLine("File: " + scanResult.Resource);
            Console.WriteLine("Scan ID: " + scanResult.ScanId);
            Console.WriteLine("Message: " + scanResult.VerboseMsg);
            DBConnect.InsertnotvtscannedTable(Program.appName, Program.fileName, scanResult.Permalink, scanResult.VerboseMsg);
        }


    }


}
