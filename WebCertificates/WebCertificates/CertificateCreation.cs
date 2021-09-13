using System;
using System.Collections.Generic;
using WebCertificates.Exceptions;
using WebCertificates.Model;
using CERTCLILib;
using CERTENROLLLib;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace WebCertificates
{
    public class CertificateCreation
    {
        // These values will be needed for our certificate enrollment process
        private const int CC_DEFAULTCONFIG = 0;
        private const int CC_UIPICKCONFIG = 0x1;
        private const int CR_IN_BASE64 = 0x1;
        private const int CR_IN_FORMATANY = 0;
        private const int CR_IN_PKCS10 = 0x100;
        private const int CR_DISP_ISSUED = 0x3;
        private const int CR_DISP_UNDER_SUBMISSION = 0x5;
        private const int CR_OUT_BASE64 = 0x1;
        private const int CR_OUT_BASE64HEADER = 0;
        private const int CR_OUT_CHAIN = 0x100;

        // These values will be needed to retrieve and remove the private key when we are done
        private const UInt32 NCRYPT_MACHINE_KEY_FLAG = 0x00000020;
        private const UInt32 CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = 0x00010000;
        private const UInt32 CRYPT_DELETEKEYSET = 0x00000010;

        // We need to p/invoke these libraries in order to work with privatekeys
        [DllImport("ncrypt.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern Int32 NCryptDeleteKey(
            [In] SafeNCryptKeyHandle hKey,
            [In] UInt32 dwFlags
            );

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern Boolean CryptAcquireContext(
           out IntPtr phProv,
           String pszContainer,
           String pszProvider,
           uint dwProvType,
           uint dwFlags
            );

        [DllImport("Advapi32.dll", EntryPoint = "CryptReleaseContext", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CryptReleaseContext(
            IntPtr hProv,
            Int32 dwFlags   // Reserved. Must be 0.
            );

        [DllImport("Crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern Boolean CryptAcquireCertificatePrivateKey(
            [In] IntPtr pCert,
            [In] UInt32 dwFlags,
            [In, Optional] IntPtr pvReserved,
            [Out] out SafeNCryptKeyHandle phCryptProv,
            [Out] out UInt32 pdwKeySpec,
            [Out] out Boolean pfCallerFreeProv
            );

        private string CreateRequest(string subject, string catemplate, CertificateRequestModel model)
        {
            // Create all objectes we need.
            CX509CertificateRequestPkcs10 Pkcs10 = new CX509CertificateRequestPkcs10();
            CX509PrivateKey PrivateKey = new CX509PrivateKey();
            CCspInformation CSP = new CCspInformation();
            CCspInformations CSPs = new CCspInformations();
            CX500DistinguishedName DN = new CX500DistinguishedName();
            CX509Enrollment Enroll = new CX509Enrollment();
            CObjectIds ObjectIds = new CObjectIds();
            CObjectId ObjectId = new CObjectId();
            CX509ExtensionKeyUsage ExtensionKeyUsage = new CX509ExtensionKeyUsage();
            CX509ExtensionEnhancedKeyUsage X509ExtensionEnhancedKeyUsage = new CX509ExtensionEnhancedKeyUsage();
            string Request;

            // Create our Cryptographic Service Provider object and add it to the CSP collection
            CSP.InitializeFromName("Microsoft RSA SChannel Cryptographic Provider");
            CSPs.Add(CSP);

            // Create our private key object
            PrivateKey.ContainerName = subject;
            PrivateKey.Length = 2048;
            PrivateKey.KeySpec = X509KeySpec.XCN_AT_KEYEXCHANGE;
            PrivateKey.KeyUsage = X509PrivateKeyUsageFlags.XCN_NCRYPT_ALLOW_ALL_USAGES;
            PrivateKey.MachineContext = true;
            PrivateKey.CspInformations = CSPs;
            PrivateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG;
            PrivateKey.ProviderType = X509ProviderType.XCN_PROV_RSA_SCHANNEL;

            PrivateKey.Create();

            // Write our private key as base64 to our model so we can use it later
            model.Privatekey = PrivateKey.Export("PRIVATEBLOB", EncodingType.XCN_CRYPT_STRING_BASE64HEADER);

            // Initialize the PKCS#10 certificate request object based on the private key
            // Set the context to machine so this cert will work with the computer certificate store
            // Pass a template to use. Because of this we do not specify extended key usage since the
            // template does this for us
            Pkcs10.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextMachine, PrivateKey, catemplate);

            // Create the Distinguished Name object with the subject name we took as input
            // and add it to our request
            DN.Encode("CN=" + subject.Trim(), X500NameFlags.XCN_CERT_NAME_STR_NONE);
            Pkcs10.Subject = DN;

            // Create our enrollment request and transform it to a string
            Enroll.InitializeFromRequest(Pkcs10);
            Request = Enroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);

            return Request;
        }

        private string SendRequest(string Request, int CertIntervalAttempts = 10, int CertIntervalSleep = (6 * 1000))
        {
            //  Create all the objects that will be required
            CCertConfig CertConfig = new CCertConfig();
            CCertRequest CertRequest = new CCertRequest();
            string CAConfig;
            int iDisposition;
            string strDisposition;
            string strCert;


            // Retrieve the system default CA to use for our request
            CAConfig = CertConfig.GetConfig(CC_DEFAULTCONFIG);

            // Submit the cert request in base64 and allow the system to figure out if Pkcs#7 or Pkcs#10
            iDisposition = CertRequest.Submit(CR_IN_BASE64 | CR_IN_FORMATANY, Request, null, CAConfig);

            int certWaitCount = 0;

            while (CR_DISP_ISSUED != iDisposition) // We are not enrolled
            {
                strDisposition = CertRequest.GetDispositionMessage();

                if (CR_DISP_UNDER_SUBMISSION == iDisposition) // Our request is pending
                {
                    if (certWaitCount > CertIntervalAttempts)
                    {
                        throw new CertificateRequestTimeoutException("The submission timed out: " + strDisposition + " Last status: " + CertRequest.GetLastStatus().ToString());
                    }
                    ++certWaitCount;
                    Thread.Sleep(CertIntervalSleep);
                    continue;
                }

                else // Our request has failed
                {
                    throw new CertificateRequestFailedException("The submission failed: " + strDisposition + " Last status: " + CertRequest.GetLastStatus().ToString());
                }

            }

            // Retrieve our cert in base64 with the entire cert chain included
            // We need the entire chain for this cert to work on Linux systems
            strCert = CertRequest.GetCertificate(CR_OUT_BASE64HEADER | CR_OUT_CHAIN);

            return strCert;
        }

        private X509Certificate2 FindCertificateInMachineStore(string SubjectDomain)
        {
            X509Certificate2 CertToFind = new X509Certificate2();
            X509Store Store = new X509Store("REQUEST", StoreLocation.LocalMachine);
            Store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection CertsFound = Store.Certificates.Find(X509FindType.FindBySubjectName, SubjectDomain, false);

            if (CertsFound.Count == 0 || CertsFound.Count >= 2)
            {
                CertToFind = null;
                return CertToFind;
            }

            Store.Close();

            return CertToFind = CertsFound[0];
        }

        public bool DeleteRequestFromStore(X509Certificate2 certificate)
        {
            X509Store Store = new X509Store("REQUEST", StoreLocation.LocalMachine);

            try
            {
                Store.Open(OpenFlags.ReadWrite);
                Store.Remove(certificate);
            }
            catch (Exception ex)
            {
                return false;
            }
            finally
            {
                Store.Close();
            }

            return true;
        }

        private bool DeleteCSPPrivatekey(AsymmetricAlgorithm Privatekey)
        {
            if (Privatekey == null)
            {
                return false;
            }

            string KeyContainer;
            string CSPName; // Cryptographic Service Provider name 
            UInt32 CSPType; // Cryptographic Serivce Provider type

            // Retrieve properties of our privatekey based on CSP (RSA or DSA)
            // This is needed for the removal step
            switch (Privatekey)
            {
                case RSACryptoServiceProvider _:
                    KeyContainer = ((RSACryptoServiceProvider)Privatekey).CspKeyContainerInfo.KeyContainerName;
                    CSPName = ((RSACryptoServiceProvider)Privatekey).CspKeyContainerInfo.ProviderName;
                    CSPType = (UInt32)((RSACryptoServiceProvider)Privatekey).CspKeyContainerInfo.ProviderType;
                    break;
                case DSACryptoServiceProvider _:
                    KeyContainer = ((DSACryptoServiceProvider)Privatekey).CspKeyContainerInfo.KeyContainerName;
                    CSPName = ((DSACryptoServiceProvider)Privatekey).CspKeyContainerInfo.ProviderName;
                    CSPType = (UInt32)((DSACryptoServiceProvider)Privatekey).CspKeyContainerInfo.ProviderType;
                    break;
                default:
                    Privatekey.Dispose();
                    return false;
            }

            IntPtr phProv = IntPtr.Zero;

            // Delete the privatekey from the local machine store
            bool KeyRemovalStatus = CryptAcquireContext(out phProv, KeyContainer, CSPName, CSPType, CRYPT_DELETEKEYSET | NCRYPT_MACHINE_KEY_FLAG);

            if (!KeyRemovalStatus)
            {
                // If we did not find a key te delete from the machine store, try the current user store to ensure clean-up
                KeyRemovalStatus = CryptAcquireContext(out phProv, KeyContainer, CSPName, CSPType, CRYPT_DELETEKEYSET);
            }

            if (phProv.ToInt32() != 0)
            {
                // If a privatekey was removed we have an open handle that we must close
                CryptReleaseContext(phProv, 0);
            }

            Privatekey.Dispose();

            return KeyRemovalStatus;
            //return false;
        }

        bool DeleteCNGPrivatekey(SafeNCryptKeyHandle phPrivatekey)
        {
            Int32 hresult = NCryptDeleteKey(phPrivatekey, 0);
            phPrivatekey.Dispose();
            return hresult == 0;
        }

        bool DeletePrivateKey(X509Certificate2 cert)
        {
            if (!CryptAcquireCertificatePrivateKey(cert.Handle, CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG, IntPtr.Zero, out SafeNCryptKeyHandle phCryptProvOrNCryptKey, out UInt32 pdwKeySpec, out Boolean _))
            {
                return false;
            }

            if (pdwKeySpec == UInt32.MaxValue)
            {
                return DeleteCNGPrivatekey(phCryptProvOrNCryptKey);
            }
            else
            {
                return DeleteCSPPrivatekey(cert.PrivateKey);
            }
        }

        public Dictionary<string, string> GetCertificate(string SubjectDomain, string CATemplate, int CertIntervalAttempts = 10, int CertIntervalSleep = (6 * 1000))
        {
            CertificateRequestModel CertRequest = new CertificateRequestModel();
            CertRequest.SubjectDomain = SubjectDomain;
            CertRequest.CaTemplate = CATemplate;

            string request;
            string certificate;

            try
            {
                request = CreateRequest(SubjectDomain, CATemplate, CertRequest);
                certificate = SendRequest(request, CertIntervalAttempts, CertIntervalSleep);
            }
            catch (Exception ex)
            {
                throw;
            }
            finally
            {
                X509Certificate2 CertToRemove = FindCertificateInMachineStore(SubjectDomain);

                if (CertToRemove != null)
                {
                    bool RemovePrivatekeyOutcome = DeletePrivateKey(CertToRemove);
                    bool RemovalOutcome = DeleteRequestFromStore(CertToRemove);
                }
                else
                {
                    throw new CertificateNotFoundException($"No certificates found or failed to remove certificates for {SubjectDomain}");
                }

            }

            CertRequest.CertRequest = request;
            CertRequest.CertWithChain = certificate;

            Dictionary<string, string> dict = new Dictionary<string, string>
            {
                { "Domain", CertRequest.SubjectDomain },
                { "CertRequest", CertRequest.CertRequest },
                { "CertWithChain", CertRequest.CertWithChain },
                { "CertPrivatekey", CertRequest.Privatekey }
            };

            return dict;
        }

    }
}
