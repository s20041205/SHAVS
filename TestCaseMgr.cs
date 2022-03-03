using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using Biosensetek.VitalSign.Persist;
using Biosensetek.VitalSign.Security;
using RetrieveFile = Biosensetek.VitalSign.Persist.RetrieveHeader;

namespace VitalSignTestCaseValidate
{
    public class TestCaseMgr
    {

        public void DisplayHelp()
        {
            Console.WriteLine("*****************************************************");
            Console.WriteLine("Choice test item #:");
            Console.WriteLine("06) DMG_UTC06\t07) LMT_UTC07\t08) REG_UTC08");
            Console.WriteLine("11) TPR_UTC11\t12) RTV_UTC12\t13) EVT_UTC13");
            Console.WriteLine("18) CYB_UTC18\t19) CYB_UTC19\t");
            Console.WriteLine("*****************************************************");
            //Console.ReadLine();
        }
        public void DisplayCYB19Help()
        {
            Console.WriteLine("*****************************************************");
            Console.WriteLine("19) CYB_UTC19");
            //Console.WriteLine(" -sha1 (input)\t\t: calculate string SHA-1");
            Console.WriteLine(" -fhash (path)\t\t : calculate file hash value (SHA-1)");
            Console.WriteLine(" -folhash (path)\t : calculate folder contents hash value (SHA-1)");
            Console.WriteLine(" -sha512 (input)\t : calculate string SHA-512");
            Console.WriteLine(" -comp (input1) (input2) : compare");
            Console.WriteLine(" -crc (path)\t\t : get file CRC checksum");
            Console.WriteLine("*****************************************************");
        }
        public string GetSHA1Hash(string str)
        {
            string hash = string.Empty;
            try
            {
                using (var sha1 = new SHA1Managed())
                {
                    hash = BitConverter.ToString(sha1.ComputeHash(Encoding.UTF8.GetBytes(str)));
                }
            }
            catch (Exception e)
            {

            }
            hash = hash.Replace("-", "").ToLower();
            return hash;
        }
        public static string GetSHA1Hash(byte[] input)
        {
            try
            {
                using (SHA1Managed sha1 = new SHA1Managed())
                {
                    var hash = sha1.ComputeHash(input);
                    var sb = new StringBuilder(hash.Length * 2);

                    foreach (byte b in hash)
                    {
                        // can be "x2" if you want lowercase
                        sb.Append(b.ToString("x2"));
                    }
                    return sb.ToString();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return "";
            }
        }
        public string GetSHA512Hash(string str)
        {
            string hash = string.Empty;
            try
            {
                using (var sha512 = new SHA512CryptoServiceProvider())
                {
                    hash = BitConverter.ToString(sha512.ComputeHash(Encoding.UTF8.GetBytes(str)));
                }
            }
            catch(Exception e)
            {

            }
            hash = hash.Replace("-", "").ToLower();
            return hash;
        }
        public string GetSHA512Hash(byte[] input)
        {
            try
            {
                SHA512 sha512 = new SHA512CryptoServiceProvider();
                var res = sha512.ComputeHash(input);
                var sb = new StringBuilder(res.Length * 2);
                foreach (byte b in res)
                {
                    // can be "x2" if you want lowercase
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return "";
            }
        }
        public Tuple<string, bool> GetFilesHash(string root, string admit, string curFile)
        {
            string path = root;
            string hash = string.Empty;
            bool curFileCheckSuccess = true;
            Regex rgx1 = new Regex(@"^([a-z0-9]{34})$");
            if (!rgx1.IsMatch(admit)) return Tuple.Create(hash, curFileCheckSuccess);
            if (!Directory.Exists(path)) return Tuple.Create(hash, curFileCheckSuccess);
            //
            List<string> lst = new List<string>();
            string[] fileEntries = Directory.GetFiles(path, "*");
            for (int i = 0; i < fileEntries.Length; i++)
            {
                if (fileEntries[i].EndsWith($".{admit}")) continue;
                if (File.Exists($"{path}\\{curFile}.vts"))
                {
                    if (fileEntries[i].EndsWith(".event"))
                        continue;
                    else if (fileEntries[i].Contains($"{curFile}.vts"))
                    {
                        if (fileEntries[i].EndsWith(".xyz")) continue;
                        bool theSame = CompareFileCheckSum(fileEntries[i]);
                        //Debug($"{fileEntries[i]} checksum={theSame}");
                        curFileCheckSuccess &= theSame;
                        continue;
                    }
                }
                string f = Path.GetFileName(fileEntries[i]);
                //Debug("adding:" + f);
                lst.Add(f);
            }
            if (lst.Count > 0)
                hash = FileHashProvider.GetFilesHash(path, lst);
            //Debug($"@FileChainMgr.GetFilesHash: lst.Count={lst.Count} =>>> hash={hash}");
            return Tuple.Create(hash, curFileCheckSuccess);
        }
        private bool CompareFileCheckSum(string fn)
        {
            //get checksum in header
            byte[] boundary = RetrieveHeaderMgr.GetHeader(fn).boundary;
            if (boundary == null || boundary.Length < 1)
                return true;
            //calculate file total bytes (w/o header) and get LSB byte
            byte byteCkSum = boundary[boundary.Length - 1];
            byte byteSum = CalculateCheckSum(fn, 200);
            //
            /*bool compare = byteCkSum.Equals(byteSum);
            string hexCkSum = string.Format("{0:X}", byteCkSum);
            string hexRes = string.Format("{0:X}", byteSum);
            Debug($"file LSB = {hexRes}, checkSum={hexCkSum} => check:{success}");*/
            return byteCkSum.Equals(byteSum);
        }
        public byte CalculateCheckSum(string fn, int header = 200)
        {
            uint len = 0;
            if (!File.Exists(fn)) return 0;
            FileInfo f = new FileInfo(fn);
            if (f.Length > 200)
                len = (uint)f.Length - 200;
            else
                return 0;
            //
            byte[] tmpRaw = new byte[len];
            ulong tmp = 0;
            try
            {
                using (FileStream fs = new FileStream(fn, FileMode.Open))
                {
                    using (BinaryReader br = new BinaryReader(fs))
                    {
                        try
                        {
                            fs.Seek(header, SeekOrigin.Begin);
                            br.Read(tmpRaw, 0, tmpRaw.Length);
                        }
                        catch (Exception ex) { System.Diagnostics.Debug.Print(ex.Message); }
                    }
                }
            }
            catch (Exception ex)
            {
                //Debug("@CalculateCheckSum exception:" + ex);
            }
            for (int i = 0; i < tmpRaw.Length; i++)
            {
                tmp += tmpRaw[i];
                if (tmp >= Int32.MaxValue / 2)
                    tmp = tmp & 0x00FF;
            }
            tmp = (uint)tmp & 0x00FF;

            return Convert.ToByte(tmp);
        }
    }
}
