using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace com.waldron.shrewReconnect.Shrew
{
    class ShrewAuthentication
    {

        private const int STARTER_DELAY = 3000;
        private const int CLEANUP_TIMEOUT = 10000; // 10 sec
        private const int RETRY_INTERVAL_MS = 5000; // 10 sec
        private const int RETRY_MAX = 5;

        private ShrewCredentials credentials { get; set; }
        private CancellationTokenSource tokenSource { get; set; }
        private Task authenticationTask { get; set; }
        private HttpClient httpClient = null;
        private Regex regexUserName = new Regex(@"((?<domain>\w+)\\)?(?<username>\w+)");


        public ShrewAuthentication(ShrewCredentials credentials)
        {
            this.credentials = credentials;
            try
            {
                WebRequestHandler requestHandler = new WebRequestHandler();
                requestHandler.AllowAutoRedirect = false;
                requestHandler.ServerCertificateValidationCallback = delegate { return true; };
                httpClient = new HttpClient(requestHandler);
            }
            catch (Exception)
            {
            }
        }

        public void Authenticate()
        {
            if (httpClient != null)
            {
                this.tokenSource = new CancellationTokenSource();
                authenticationTask = AuthenticateProcess();
            }
            else
            {
                ShrewNotifier.Log("WEB connection error for Authentication ...", ShrewConnectionStatus.Disconnected);
            }
        }

        private Task AuthenticateProcess()
        {
            return Task.Run(async () => { 
                int failedAuthAttempts = 0;
                Boolean authenticated = false;
                await Task.Delay(STARTER_DELAY, tokenSource.Token);
                while (!(authenticated = await tryAuth()) && ++failedAuthAttempts <= RETRY_MAX && !tokenSource.IsCancellationRequested)  
                {
                    ShrewNotifier.Log("Auth retry #" + failedAuthAttempts +" of " + RETRY_MAX + " in " + RETRY_INTERVAL_MS + " ms ...", ShrewConnectionStatus.Pending);
                    await Task.Delay(RETRY_INTERVAL_MS, tokenSource.Token);
                }
                if (authenticated)
                {
                    ShrewNotifier.Log("Auth on " + this.credentials.formLogin  + " done.", ShrewConnectionStatus.Connected);
                }
                else
                {
                    ShrewNotifier.Log("Auth on " + this.credentials.formLogin + " failed!", ShrewConnectionStatus.Disconnected);
                }
                ShrewNotifier.Log("------------------------------------------------", ShrewConnectionStatus.Pending);
            }, tokenSource.Token);
        }

        private async Task<bool> tryAuth()
        {
            bool authenticated = false;
            ShrewNotifier.Log("Trying to auth on " + this.credentials.formLogin + " ...", ShrewConnectionStatus.Pending);
            try
            {
                Uri formUri = null;
                using (HttpResponseMessage response = await httpClient.GetAsync(this.credentials.formLogin))
                {
                    String content = await response.Content.ReadAsStringAsync();
                    formUri = response.Headers.Location;
                }
                String username = regexUserName.Match(this.credentials.username).Groups["username"].Value;
                String password = this.credentials.password;

                using (HttpResponseMessage response = await httpClient.GetAsync(formUri))
                {
                    String content = await response.Content.ReadAsStringAsync();
                    bool status = response.IsSuccessStatusCode;
                }
                String url = formUri.AbsoluteUri.Replace(formUri.PathAndQuery, "/");
                String token = formUri.Query.Substring(1);

                var data = new Dictionary<string, string>
                {
                    { "4Tredir", this.credentials.formLogin },
                    { "magic", token },
                    { "username", username },
                    { "password",  password}
                };
                using (HttpResponseMessage response = await httpClient.PostAsync(url, new FormUrlEncodedContent(data)))
                {
                    String content = await response.Content.ReadAsStringAsync();
                    authenticated = response.IsSuccessStatusCode;
                }
            }
            catch (Exception exc)
            {
                authenticated = false;
                ShrewNotifier.Log("Auth: " + exc.Message, ShrewConnectionStatus.Disconnected);
            }
            return authenticated;
        }

        public void cleanUp()
        {
            try
            {
                if (tokenSource != null && !tokenSource.IsCancellationRequested)
                {
                    tokenSource.Cancel();
                }
                authenticationTask.Wait(CLEANUP_TIMEOUT);
            }
            catch(Exception)
            {
            }
            finally
            {
                try
                {
                    if(tokenSource != null)
                    {
                        tokenSource.Dispose();
                    }
                }
                catch (Exception) { }
                tokenSource = null;
            }
        }
    }
}
