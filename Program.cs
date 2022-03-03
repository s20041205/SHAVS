using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Biosensetek.VitalSign.Security;

namespace VitalSignTestCaseValidate
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args)
        {
            TestCaseMgr mgr = new TestCaseMgr();
            //mgr.DisplayHelp();
            //for test
            args = new string[3];
            args[0] = "19";
            args[1] = "-crc";
            args[2] = @"C:\VitalData\[VT-Trace]\c4de9ea95c12fef0dd776fd3070a0cc40e\33d4b8ea60756951806481cc208e732fc3\4e5859816d2cf3421fdf90901e01838dc5.vts";
            //
            if (args.Length == 0)
            {
                Console.WriteLine("Argument required!");
                mgr.DisplayHelp();
            }
            if (args.Length > 0)
            {
                if (args.Length == 1)
                {
                    if ("h".Equals(args[0].ToLower()) || "-h".Equals(args[0].ToLower()))
                    {
                        mgr.DisplayHelp();
                    }
                    else if ("19".Equals(args[0].ToLower()))
                    {
                        mgr.DisplayCYB19Help();
                    }
                }
                else if (args.Length == 2)
                {
                    string itm = args[0];
                    string key = args[1];
                    //
                    switch (itm)
                    {
                        case "19":
                            if ("-h".Equals(key.ToLower()))
                            {
                                mgr.DisplayCYB19Help();
                            }
                            break;
                    }
                }
                else if (args.Length == 3)
                {
                    string itm = args[0];
                    string key = args[1];
                    string str = args[2];
                    if ("19".Equals(itm.ToLower()) && "-sha1".Equals(key.ToLower()))//not using
                    {
                        string encryp = mgr.GetSHA1Hash(str);
                        Console.WriteLine($"\n[Calculate SHA-1]");
                        Console.WriteLine($"-sha1 {str} \n=> {encryp}");
                    }
                    else if ("19".Equals(itm.ToLower()) && "-fhash".Equals(key.ToLower()))
                    {
                        string encryp = FileHashProvider.GetFileHash(str);
                        Console.WriteLine($"\n[Calculate file hash (SHA-1)]");
                        Console.WriteLine($"-fhash {str} \n=> {encryp}");
                    }
                    else if ("19".Equals(itm.ToLower()) && "-folhash".Equals(key.ToLower()))
                    {
                        List<string> lst = new List<string>();
                        string[] fileEntries = Directory.GetFiles(str, "*");
                        for (int i = 0; i < fileEntries.Length; i++)
                        {
                            string f = Path.GetFileName(fileEntries[i]);
                            //Console.WriteLine("adding:" + f);
                            lst.Add(f);
                        }
                        string encryp = FileHashProvider.GetFilesHash(str, lst);
                        Console.WriteLine($"\n[Calculate folder contents hash (SHA-1)]");
                        Console.WriteLine($"-folhash {str} \n=> {encryp}");
                    }
                    else if ("19".Equals(itm.ToLower()) && "-sha512".Equals(key.ToLower()))
                    {
                        string encryp = mgr.GetSHA512Hash(str);
                        Console.WriteLine($"\n[Calculate SHA-512]");
                        Console.WriteLine($"-sha512 {str} \n=> {encryp}");
                    }
                    else if ("19".Equals(itm.ToLower()) && "-crc".Equals(key.ToLower()))
                    {
                        byte ckcsum = mgr.CalculateCheckSum(str);
                        Console.WriteLine($"\n[Calculate CRC checksum]");
                        string strCRC = string.Format("{0:X}", ckcsum);
                        Console.WriteLine($"-crc {str} \n=> {strCRC}");
                    }
                }
                else if (args.Length == 4)
                {
                    string itm = args[0];
                    string key = args[1];
                    string input1 = args[2];
                    string input2 = args[3];
                    if ("19".Equals(itm.ToLower()) && "-comp".Equals(key.ToLower()))
                    {
                        bool isSame = input1.Equals(input2);
                        Console.WriteLine($"{input1} vs. {input2} => {isSame}");
                    }
                }
            }
            
        }
        
    }
}
