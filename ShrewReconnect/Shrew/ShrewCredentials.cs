﻿namespace com.waldron.shrewReconnect
{
    public class ShrewCredentials
    {
        public string siteConfigPath { get; set; }
        public string username { get; set; }
        public string password { get; set; }
        public string formLogin { get; set; }
        public bool connectOnStart { get; set; }
        public bool authenticateOnConnected { get; set; }
    }
}
