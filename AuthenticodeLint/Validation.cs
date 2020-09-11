using System;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using System.IO;

namespace AuthenticodeLinter
{
    class Validation
    {
        public static int validateWithSignTool(String fileName, int signatureIndex, string thumbprint)
        {
            string output = "";
            string err = "";
            int verified = 0;
            int signed = 0;
            int error = 0;
            int warning = 0;
            int ts = 0;
            int tsVerified = 0;

            // Prepare the process to run
            ProcessStartInfo start = new ProcessStartInfo();
            // Enter in the command line arguments, everything you would enter after the executable name itself
            Console.WriteLine(fileName);
            start.Arguments = "verify /pa /debug /v /ds " + signatureIndex + " " + fileName;
            // Enter the executable to run, including the complete path
            start.FileName = "C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.18362.0\\x64\\signtool.exe";
            // Do you want to show a console window?
           // start.WindowStyle = ProcessWindowStyle.Hidden;
          //  start.CreateNoWindow = true;
           start.RedirectStandardOutput = true;
          start.RedirectStandardError = true;
            int exitCode = 0;


            // Run the external process & wait for it to finish
            using (Process proc = Process.Start(start))
            {

                 output = proc.StandardOutput.ReadToEnd();
                Console.WriteLine(output);
                 err = proc.StandardError.ReadToEnd();

                    // Retrieve the app's exit code
                    proc.WaitForExit();
                    exitCode = proc.ExitCode;
                    Console.WriteLine("Exit Code: " + exitCode);
                if (err.Contains("No signature found"))
                    signed = 0;
                else
                    signed = 1;
                if (output.Contains("Number of files successfully Verified: 0"))
                    verified = 0;
                if (output.Contains("Number of files successfully Verified: 1"))
                    verified = 1;
                if (output.Contains("Number of warnings: 1"))
                    warning = 1;
                if (output.Contains("Number of errors: 1"))
                    error = 1;
                if (output.Contains("The signature is timestamped"))
                    ts = 1;
                if (output.Contains("Timestamp Verified by"))
                    tsVerified = 1;

                    DBConnect.InsertSigntoolValidationTable(Program.appName, Program.fileName, verified, signed, error, warning, err, output, ts, tsVerified, thumbprint, signatureIndex );

            }
            return exitCode;
        }

        public static int validateWithSigcheck(String fileName)
        {
            string output = "";
            string err = "";
            int verified = 0;
            int signed = 0;

            // Prepare the process to run
            ProcessStartInfo start = new ProcessStartInfo();
            // Enter in the command line arguments, everything you would enter after the executable name itself
            Console.WriteLine(fileName);
            start.Arguments = "-a " + fileName;
            // Enter the executable to run, including the complete path
            start.FileName = "C:\\Users\\user\\Downloads\\Sigcheck\\sigcheck64.exe";
            // Do you want to show a console window?
            // start.WindowStyle = ProcessWindowStyle.Hidden;
            //  start.CreateNoWindow = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            int exitCode = 0;


            // Run the external process & wait for it to finish
            using (Process proc = Process.Start(start))
            {

                output = proc.StandardOutput.ReadToEnd();
                Console.WriteLine(output);
                err = proc.StandardError.ReadToEnd();

                // Retrieve the app's exit code
                proc.WaitForExit();
                exitCode = proc.ExitCode;
                Console.WriteLine("Exit Code: " + exitCode);
                if (output.Contains("Verified:	Signed"))
                {
                    verified = 1;
                    signed = 1;
                }

                DBConnect.InsertSigcheckValidationTable(Program.appName, Program.fileName, verified, signed, err, output);

            }
            return exitCode;
        }
        public static void validate(String fileName, int signatureIndex, String thumbprint)
        {
            validateWithSigcheck(fileName);
            validateWithSignTool(fileName, signatureIndex, thumbprint);
        }
    }
}
