using System;
using System.IO;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;

using Prism.Mvvm;
using Prism.Commands;

namespace EncryptServerTest
{
    public class MainWindowM : BindableBase
    {
        public Client Client { get; set; }

        public Server Server { get; set; }

        public MainWindowM()
        {
            Task.Run(() => Server = new Server());
            Task.Run(() => Client = new Client());
        }
    }

    public class Client : BindableBase
    {
        private string text = "";
        public string Text
        {
            get { return text; }
            set {
                this.SetProperty(ref text, value);
            }
        }

        private string encrypted = "";
        public string Encrypted
        {
            get { return encrypted; }
            set { this.SetProperty(ref encrypted, value); }
        }

        private string publicKey;

        private Aes aes;

        public DelegateCommand SendCommand { get; set; }

        public Client()
        {
            SendCommand = new DelegateCommand(StartClient);

            aes = Aes.Create();
        }

        public void StartClient()
        {
            try
            {
                var client = new TcpClient("127.0.0.1", 11000);

                ReadPublicKey(client);

                SendCommonKey(client);

                SendText(client);
            }
            catch(Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e.ToString());
            }
        }

        private void ReadPublicKey(TcpClient client)
        {
            var ns = client.GetStream();

            byte[] buffer = new byte[1024];

            int bytesRead = ns.Read(buffer, 0, buffer.Length);

            if (bytesRead == 0)
            {
                client.Close();
                return;
            }

            var data = new byte[bytesRead];

            Array.Copy(buffer, 0, data, 0, bytesRead);

            publicKey = Encoding.UTF8.GetString(data);
        }

        private void SendCommonKey(TcpClient client)
        {
            var ns = client.GetStream();

            var buffer = new byte[1024];

            int bytesRead;
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKey);

                var iv = rsa.Encrypt(aes.IV, false);
                ns.Write(iv, 0, iv.Length);
                bytesRead = ns.Read(buffer, 0, buffer.Length);
                if(bytesRead == 0)
                {
                    client.Close();
                    return;
                }

                var key = rsa.Encrypt(aes.Key, false);
                ns.Write(key, 0, key.Length);
                bytesRead = ns.Read(buffer, 0, buffer.Length);
                if(bytesRead == 0)
                {
                    client.Close();
                    return;
                }
            }
        }

        private void SendText(TcpClient client)
        {
            var ns = client.GetStream();

            using CryptoStream cryptStream = new CryptoStream(ns, aes.CreateEncryptor(), CryptoStreamMode.Write);

            using StreamWriter sWriter = new StreamWriter(cryptStream);

            sWriter.Write(Text);
        }
    }

    public class Server : BindableBase
    {
        public static ManualResetEvent allDone = new ManualResetEvent(false);

        private string publicKey, privateKey;

        private Aes aes;

        private byte[] iv, key;

        private string text = "";
        public string Text
        {
            get { return text; }
            set { this.SetProperty(ref text, value); }
        }

        private string encrypted = "";
        public string Encrypted
        {
            get { return encrypted; }
            set { this.SetProperty(ref encrypted, value); }
        }

        public Server()
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                publicKey = rsa.ToXmlString(false);
                privateKey = rsa.ToXmlString(true);
            }

            aes = Aes.Create();

            StartListening();
        }

        public void StartListening()
        {
            IPAddress ipAddress = IPAddress.Parse("127.0.0.1");
            var listener = new TcpListener(ipAddress, 11000);

            try
            {
                listener.Start();

                Accept(listener);
            } catch (Exception e)
            {
                System.Diagnostics.Debug.WriteLine(e.ToString());
            }

            System.Diagnostics.Debug.WriteLine("End");
        }

        private async void Accept(TcpListener listener)
        {
            while(true)
            {
                TcpClient client = await listener.AcceptTcpClientAsync();

                AcceptClient(client);
            }
        }

        private void AcceptClient(TcpClient client)
        {
            SendPublicKey(client);

            ReceiveCommonKey(client);

            ReceiveText(client);
        }

        private void SendPublicKey(TcpClient client)
        {
            var ns = client.GetStream();

            byte[] data = Encoding.UTF8.GetBytes(publicKey);

            ns.Write(data, 0, data.Length);
        }

        private void ReceiveCommonKey(TcpClient client)
        {
            var ns = client.GetStream();

            byte[] buffer;
            int bytesRead;
            
            buffer = new byte[1024];
            bytesRead = ns.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0)
            {
                client.Close();
                return;
            }

            iv = Decrypt(buffer, bytesRead);

            ns.Write(new byte[] { 0 }, 0, 1);

            buffer = new byte[1024];
            bytesRead = ns.Read(buffer, 0, buffer.Length);
            if (bytesRead == 0)
            {
                client.Close();
                return;
            }

            key = Decrypt(buffer, bytesRead);

            ns.Write(new byte[] { 0 }, 0, 1);
        }

        private byte[] Decrypt(byte[] buffer, int bytesRead)
        {
            var temp = new byte[bytesRead];
            Array.Copy(buffer, 0, temp, 0, bytesRead);

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKey);
                return rsa.Decrypt(temp, false);
            }
        }

        private void ReceiveText(TcpClient client)
        {
            var ns = client.GetStream();

            char[] buffer = new char[1024];

            using CryptoStream cryptStream = new CryptoStream(
                ns,
                aes.CreateDecryptor(key, iv),
                CryptoStreamMode.Read);

            using StreamReader sReader = new StreamReader(cryptStream);

            var charsRead = sReader.Read(buffer, 0, buffer.Length);

            if(charsRead == 0)
            {
                client.Close();
                return;
            }

            Text = new string(buffer);
        }
    }
}
