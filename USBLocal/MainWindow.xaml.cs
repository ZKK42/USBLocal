using mshtml;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Navigation;
using System.Windows.Threading;

namespace USBLocal
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        private BackgroundWorker backgroundWorker1 = new BackgroundWorker();
        private BackgroundWorker backgroundWorker2 = new BackgroundWorker();
        private BackgroundWorker backgroundWorker3 = new BackgroundWorker();
        DispatcherTimer dispatcherTimer = new DispatcherTimer();
        bool apacherenk = false;
        bool mysqlrenk = false;
        public MainWindow()
        {
            InitializeComponent();
            //Web Browser script error hatasını gidermek için
            webbrowser.Navigated += new NavigatedEventHandler(webbrowser_Navigated);
            //Renk Kontrol
            backgroundWorker1.WorkerReportsProgress = true;
            backgroundWorker1.WorkerSupportsCancellation = true;
            backgroundWorker1.DoWork += new DoWorkEventHandler(backgroundWorker1_DoWork);
            backgroundWorker1.RunWorkerCompleted += new RunWorkerCompletedEventHandler(backgroundWorker1_RunWorkerCompleted);
            backgroundWorker1.ProgressChanged += new ProgressChangedEventHandler(backgroundWorker1_ProgressChanged);
            //Zaman Kontrol
            dispatcherTimer.Tick += new EventHandler(dispatcherTimer_Tick);
            dispatcherTimer.Interval = new TimeSpan(0, 0, 1);
            //Apache Kontrol
            backgroundWorker2.WorkerReportsProgress = true;
            backgroundWorker2.WorkerSupportsCancellation = true;
            backgroundWorker2.DoWork += new DoWorkEventHandler(backgroundWorker2_DoWork);
            backgroundWorker2.RunWorkerCompleted += new RunWorkerCompletedEventHandler(backgroundWorker2_RunWorkerCompleted);
            backgroundWorker2.ProgressChanged += new ProgressChangedEventHandler(backgroundWorker2_ProgressChanged);
            //Mysql Kontrol
            backgroundWorker3.WorkerReportsProgress = true;
            backgroundWorker3.WorkerSupportsCancellation = true;
            backgroundWorker3.DoWork += new DoWorkEventHandler(backgroundWorker3_DoWork);
            backgroundWorker3.RunWorkerCompleted += new RunWorkerCompletedEventHandler(backgroundWorker3_RunWorkerCompleted);
            backgroundWorker3.ProgressChanged += new ProgressChangedEventHandler(backgroundWorker3_ProgressChanged);
        }
        /* 
         //Web Browser script error hatasını gidermek için aşağıdaki aşagıdaki 3 metod kullanılmıştır.
         webbrowser_Navigated
         SetSilent
         [ComImport, Guid("6D5140C1-7436-11CE-8034-00AA006009FA"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
         IOleServiceProvider
        */
        void webbrowser_Navigated(object sender, NavigationEventArgs e)
        {
            SetSilent(webbrowser, true);
        }
        public static void SetSilent(WebBrowser browser, bool silent)
        {
            if (browser == null)
                throw new ArgumentNullException("browser");
            IOleServiceProvider sp = browser.Document as IOleServiceProvider;
            if (sp != null)
            {
                Guid IID_IWebBrowserApp = new Guid("0002DF05-0000-0000-C000-000000000046");
                Guid IID_IWebBrowser2 = new Guid("D30C1661-CDAF-11d0-8A3E-00C04FC9E26E");
                object webBrowser;
                sp.QueryService(ref IID_IWebBrowserApp, ref IID_IWebBrowser2, out webBrowser);
                if (webBrowser != null)
                {
                    webBrowser.GetType().InvokeMember("Silent", BindingFlags.Instance | BindingFlags.Public | BindingFlags.PutDispProperty, null, webBrowser, new object[] { silent });
                }
            }
        }
        [ComImport, Guid("6D5140C1-7436-11CE-8034-00AA006009FA"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
        private interface IOleServiceProvider
        {
            [PreserveSig]
            int QueryService([In] ref Guid guidService, [In] ref Guid riid, [MarshalAs(UnmanagedType.IDispatch)] out object ppvObject);
        }

        public void httpd_conf_olustur()
        {
            try
            {
                string yol = Environment.CurrentDirectory + @"\dosyalar\apache\conf\httpd.conf";
                string text = "";
                text = "Define SRVROOT \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache\"" + Environment.NewLine;
                text += "ServerRoot \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache\"" + Environment.NewLine;
                text += "Listen 88" + Environment.NewLine;
                text += "LoadModule access_compat_module modules/mod_access_compat.so" + Environment.NewLine;
                text += "LoadModule actions_module modules/mod_actions.so" + Environment.NewLine;
                text += "LoadModule alias_module modules/mod_alias.so" + Environment.NewLine;
                text += "LoadModule allowmethods_module modules/mod_allowmethods.so" + Environment.NewLine;
                text += "LoadModule asis_module modules/mod_asis.so" + Environment.NewLine;
                text += "LoadModule auth_basic_module modules/mod_auth_basic.so" + Environment.NewLine;
                text += "LoadModule authn_core_module modules/mod_authn_core.so" + Environment.NewLine;
                text += "LoadModule authn_file_module modules/mod_authn_file.so" + Environment.NewLine;
                text += "LoadModule authz_core_module modules/mod_authz_core.so" + Environment.NewLine;
                text += "LoadModule authz_groupfile_module modules/mod_authz_groupfile.so" + Environment.NewLine;
                text += "LoadModule authz_host_module modules/mod_authz_host.so" + Environment.NewLine;
                text += "LoadModule authz_user_module modules/mod_authz_user.so" + Environment.NewLine;
                text += "LoadModule autoindex_module modules/mod_autoindex.so" + Environment.NewLine;
                text += "LoadModule cgi_module modules/mod_cgi.so" + Environment.NewLine;
                text += "LoadModule dav_lock_module modules/mod_dav_lock.so" + Environment.NewLine;
                text += "LoadModule dir_module modules/mod_dir.so" + Environment.NewLine;
                text += "LoadModule env_module modules/mod_env.so" + Environment.NewLine;
                text += "LoadModule headers_module modules/mod_headers.so" + Environment.NewLine;
                text += "LoadModule include_module modules/mod_include.so" + Environment.NewLine;
                text += "LoadModule info_module modules/mod_info.so" + Environment.NewLine;
                text += "LoadModule isapi_module modules/mod_isapi.so" + Environment.NewLine;
                text += "LoadModule log_config_module modules/mod_log_config.so" + Environment.NewLine;
                text += "LoadModule cache_disk_module modules/mod_cache_disk.so" + Environment.NewLine;
                text += "LoadModule mime_module modules/mod_mime.so" + Environment.NewLine;
                text += "LoadModule negotiation_module modules/mod_negotiation.so" + Environment.NewLine;
                text += "LoadModule proxy_module modules/mod_proxy.so" + Environment.NewLine;
                text += "LoadModule proxy_ajp_module modules/mod_proxy_ajp.so" + Environment.NewLine;
                text += "LoadModule rewrite_module modules/mod_rewrite.so" + Environment.NewLine;
                text += "LoadModule setenvif_module modules/mod_setenvif.so" + Environment.NewLine;
                text += "LoadModule socache_shmcb_module modules/mod_socache_shmcb.so" + Environment.NewLine;
                text += "LoadModule ssl_module modules/mod_ssl.so" + Environment.NewLine;
                text += "LoadModule status_module modules/mod_status.so" + Environment.NewLine;
                text += "LoadModule version_module modules/mod_version.so" + Environment.NewLine;
                text += "<IfModule unixd_module>" + Environment.NewLine;
                text += "User daemon" + Environment.NewLine;
                text += "Group daemon" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "ServerAdmin postmaster@localhost" + Environment.NewLine;
                text += "ServerName localhost:88" + Environment.NewLine;
                text += "<Directory />" + Environment.NewLine;
                text += "    AllowOverride none" + Environment.NewLine;
                text += "    Require all denied" + Environment.NewLine;
                text += "</Directory>" + Environment.NewLine;
                text += "DocumentRoot \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/htdocs\"" + Environment.NewLine;
                text += "<Directory \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/htdocs\">" + Environment.NewLine;
                text += "    Options Indexes FollowSymLinks Includes ExecCGI" + Environment.NewLine;
                text += "    AllowOverride All" + Environment.NewLine;
                text += "    Require all granted" + Environment.NewLine;
                text += "</Directory>" + Environment.NewLine;
                text += "<IfModule dir_module>" + Environment.NewLine;
                text += "   DirectoryIndex index.php index.pl index.cgi index.asp index.shtml index.html index.htm \\" + Environment.NewLine;
                text += "                   default.php default.pl default.cgi default.asp default.shtml default.html default.htm \\" + Environment.NewLine;
                text += "                   home.php home.pl home.cgi home.asp home.shtml home.html home.htm" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "<Files \".ht*\">" + Environment.NewLine;
                text += "    Require all denied" + Environment.NewLine;
                text += "</Files>" + Environment.NewLine;
                text += "ErrorLog \"logs/error.log\"" + Environment.NewLine;
                text += "LogLevel warn" + Environment.NewLine;
                text += "<IfModule log_config_module>" + Environment.NewLine;
                text += "    LogFormat \"%h %l %u %t \\\"%r\\\" %>s %b \\\"%{Referer}i\\\" \\\"%{User-Agent}i\\\"\" combined" + Environment.NewLine;
                text += "    LogFormat \"%h %l %u %t \\\"%r\\\" %>s %b\" common" + Environment.NewLine;
                text += "    <IfModule logio_module>" + Environment.NewLine;
                text += "      LogFormat \"%h %l %u %t \\\"%r\\\" %>s %b \\\"%{Referer}i\\\" \\\"%{User-Agent}i\\\" %I %O\" combinedio" + Environment.NewLine;
                text += "    </IfModule>" + Environment.NewLine;
                text += "    CustomLog \"logs/access.log\" combined" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "<IfModule alias_module>" + Environment.NewLine;
                text += "    ScriptAlias /cgi-bin/ \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/cgi-bin\"" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "<IfModule cgid_module>" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "<Directory \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/cgi-bin\">" + Environment.NewLine;
                text += "    AllowOverride All" + Environment.NewLine;
                text += "    Options None" + Environment.NewLine;
                text += "    Require all granted" + Environment.NewLine;
                text += "</Directory>" + Environment.NewLine;
                text += "<IfModule headers_module>" + Environment.NewLine;
                text += "    RequestHeader unset Proxy early" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "<IfModule mime_module>" + Environment.NewLine;
                text += "    TypesConfig conf/mime.types" + Environment.NewLine;
                text += "    AddType application/x-compress .Z" + Environment.NewLine;
                text += "    AddType application/x-gzip .gz .tgz" + Environment.NewLine;
                text += "    AddHandler cgi-script .cgi .pl .asp" + Environment.NewLine;
                text += "    AddType text/html .shtml" + Environment.NewLine;
                text += "    AddOutputFilter INCLUDES .shtml" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "<IfModule mime_magic_module>" + Environment.NewLine;
                text += "    MIMEMagicFile \"conf/magic\"" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "Include conf/extra/httpd-mpm.conf" + Environment.NewLine;
                text += "Include conf/extra/httpd-multilang-errordoc.conf" + Environment.NewLine;
                text += "Include conf/extra/httpd-autoindex.conf" + Environment.NewLine;
                text += "Include conf/extra/httpd-languages.conf" + Environment.NewLine;
                text += "Include conf/extra/httpd-userdir.conf" + Environment.NewLine;
                text += "Include conf/extra/httpd-info.conf" + Environment.NewLine;
                text += "Include conf/extra/httpd-vhosts.conf" + Environment.NewLine;
                text += "Include \"conf/extra/httpd-proxy.conf\"" + Environment.NewLine;
                text += "Include \"conf/extra/httpd-default.conf\"" + Environment.NewLine;
                text += "Include \"conf/extra/httpd-xampp.conf\"" + Environment.NewLine;
                text += "<IfModule proxy_html_module>" + Environment.NewLine;
                text += "Include conf/extra/proxy-html.conf" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "Include conf/extra/httpd-ssl.conf" + Environment.NewLine;
                text += "<IfModule ssl_module>" + Environment.NewLine;
                text += "SSLRandomSeed startup builtin" + Environment.NewLine;
                text += "SSLRandomSeed connect builtin" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "AcceptFilter http none" + Environment.NewLine;
                text += "AcceptFilter https none" + Environment.NewLine;
                text += "<IfModule mod_proxy.c>" + Environment.NewLine;
                text += "<IfModule mod_proxy_ajp.c>" + Environment.NewLine;
                text += "Include \"conf/extra/httpd-ajp.conf\"" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "</IfModule>";
                File.WriteAllText(yol, text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        public void httpd_ssl_conf_olustur()
        {
            try
            {
                string yol = Environment.CurrentDirectory + @"\dosyalar\apache\conf\extra\httpd-ssl.conf";
                string text = "";
                text = "Listen 4433" + Environment.NewLine;
                text += "SSLCipherSuite HIGH:MEDIUM:!MD5:!RC4:!3DES" + Environment.NewLine;
                text += "SSLProxyCipherSuite HIGH:MEDIUM:!MD5:!RC4:!3DES" + Environment.NewLine;
                text += "SSLHonorCipherOrder on " + Environment.NewLine;
                text += "SSLProtocol all -SSLv3" + Environment.NewLine;
                text += "SSLProxyProtocol all -SSLv3" + Environment.NewLine;
                text += "SSLPassPhraseDialog  builtin" + Environment.NewLine;
                text += "SSLSessionCache \"shmcb:" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache/logs/ssl_scache(512000)\"" + Environment.NewLine;
                text += "SSLSessionCacheTimeout  300" + Environment.NewLine;
                text += "<VirtualHost _default_:4433>" + Environment.NewLine;
                text += "DocumentRoot \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/htdocs\"" + Environment.NewLine;
                text += "ServerName www.example.com:4433" + Environment.NewLine;
                text += "ServerAdmin admin@example.com" + Environment.NewLine;
                text += "ErrorLog \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache/logs/error.log\"" + Environment.NewLine;
                text += "TransferLog \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache/logs/access.log\"" + Environment.NewLine;
                text += "SSLEngine on" + Environment.NewLine;
                text += "SSLCertificateFile \"conf/ssl.crt/server.crt\"" + Environment.NewLine;
                text += "SSLCertificateKeyFile \"conf/ssl.key/server.key\"" + Environment.NewLine;
                text += "<FilesMatch \"\\.(cgi|shtml|phtml|php)$\">" + Environment.NewLine;
                text += "    SSLOptions +StdEnvVars" + Environment.NewLine;
                text += "</FilesMatch>" + Environment.NewLine;
                text += "<Directory \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache/cgi-bin\">" + Environment.NewLine;
                text += "    SSLOptions +StdEnvVars" + Environment.NewLine;
                text += "</Directory>" + Environment.NewLine;
                text += "BrowserMatch \"MSIE [2-5]\" \\" + Environment.NewLine;
                text += "         nokeepalive ssl-unclean-shutdown \\" + Environment.NewLine;
                text += "         downgrade-1.0 force-response-1.0" + Environment.NewLine;
                text += "CustomLog \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache/logs/ssl_request.log\" \\" + Environment.NewLine;
                text += "          \"%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \\\"%r\\\" %b\"" + Environment.NewLine;
                text += "</VirtualHost>";
                File.WriteAllText(yol, text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        public void config_inc_php_olustur()
        {
            try
            {
                string yol = Environment.CurrentDirectory + @"\dosyalar\phpMyAdmin\config.inc.php";
                string text = "";
                text = "<?php" + Environment.NewLine;
                text += "$cfg['blowfish_secret'] = 'zkk';" + Environment.NewLine;
                text += "$i = 0;" + Environment.NewLine;
                text += "$i++;" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['port'] = '3307';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['auth_type'] = 'config';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['user'] = 'root';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['password'] = '';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['extension'] = 'mysqli';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['AllowNoPassword'] = true;" + Environment.NewLine;
                text += "$cfg['Lang'] = '';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['host'] = '127.0.0.1';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['connect_type'] = 'tcp';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['controluser'] = 'pma';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['controlpass'] = '';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['pmadb'] = 'phpmyadmin';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['bookmarktable'] = 'pma__bookmark';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['relation'] = 'pma__relation';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['table_info'] = 'pma__table_info';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['table_coords'] = 'pma__table_coords';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['pdf_pages'] = 'pma__pdf_pages';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['column_info'] = 'pma__column_info';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['history'] = 'pma__history';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['designer_coords'] = 'pma__designer_coords';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['tracking'] = 'pma__tracking';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['userconfig'] = 'pma__userconfig';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['recent'] = 'pma__recent';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['table_uiprefs'] = 'pma__table_uiprefs';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['users'] = 'pma__users';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['usergroups'] = 'pma__usergroups';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['navigationhiding'] = 'pma__navigationhiding';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['savedsearches'] = 'pma__savedsearches';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['central_columns'] = 'pma__central_columns';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['designer_settings'] = 'pma__designer_settings';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['export_templates'] = 'pma__export_templates';" + Environment.NewLine;
                text += "$cfg['Servers'][$i]['favorite'] = 'pma__favorite';" + Environment.NewLine;
                text += "?>";
                File.WriteAllText(yol, text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }


        public void php_ini_olustur()
        {
            try
            {
                string yol = Environment.CurrentDirectory + @"\dosyalar\php\php.ini";
                string text = "";
                text += "[PHP]" + Environment.NewLine;
                text += "engine=On" + Environment.NewLine;
                text += "short_open_tag=Off" + Environment.NewLine;
                text += "precision=14" + Environment.NewLine;
                text += "output_buffering=4096" + Environment.NewLine;
                text += "zlib.output_compression=Off" + Environment.NewLine;
                text += "implicit_flush=Off" + Environment.NewLine;
                text += "unserialize_callback_func=" + Environment.NewLine;
                text += "serialize_precision=-1" + Environment.NewLine;
                text += "disable_functions=" + Environment.NewLine;
                text += "disable_classes=" + Environment.NewLine;
                text += "zend.enable_gc=On" + Environment.NewLine;
                text += "expose_php=On" + Environment.NewLine;
                text += "max_execution_time=120" + Environment.NewLine;
                text += "max_input_time=60" + Environment.NewLine;
                text += "memory_limit=512M" + Environment.NewLine;
                text += "error_reporting=E_ALL & ~E_DEPRECATED & ~E_STRICT" + Environment.NewLine;
                text += "display_errors=On" + Environment.NewLine;
                text += "display_startup_errors=On" + Environment.NewLine;
                text += "log_errors=On" + Environment.NewLine;
                text += "log_errors_max_len=1024" + Environment.NewLine;
                text += "ignore_repeated_errors=Off" + Environment.NewLine;
                text += "ignore_repeated_source=Off" + Environment.NewLine;
                text += "report_memleaks=On" + Environment.NewLine;
                text += "html_errors=On" + Environment.NewLine;
                text += "variables_order=\"GPCS\"" + Environment.NewLine;
                text += "request_order=\"GP\"" + Environment.NewLine;
                text += "register_argc_argv=Off" + Environment.NewLine;
                text += "auto_globals_jit=On" + Environment.NewLine;
                text += "post_max_size=40M" + Environment.NewLine;
                text += "auto_prepend_file=" + Environment.NewLine;
                text += "auto_append_file=" + Environment.NewLine;
                text += "default_mimetype=\"text/html\"" + Environment.NewLine;
                text += "default_charset=\"UTF-8\"" + Environment.NewLine;
                text += "include_path=" + Environment.CurrentDirectory + "\\dosyalar\\php\\PEAR" + Environment.NewLine;
                text += "doc_root=" + Environment.NewLine;
                text += "user_dir=" + Environment.NewLine;
                text += "extension_dir=\"" + Environment.CurrentDirectory + "\\dosyalar\\php\\ext\"" + Environment.NewLine;
                text += "enable_dl=Off" + Environment.NewLine;
                text += "file_uploads=On" + Environment.NewLine;
                text += "upload_tmp_dir=\"" + Environment.CurrentDirectory + "\\dosyalar\\tmp\"" + Environment.NewLine;
                text += "upload_max_filesize=40M" + Environment.NewLine;
                text += "max_file_uploads=20" + Environment.NewLine;
                text += "allow_url_fopen=On" + Environment.NewLine;
                text += "allow_url_include=Off" + Environment.NewLine;
                text += "default_socket_timeout=60" + Environment.NewLine;
                text += "extension=bz2" + Environment.NewLine;
                text += "extension=curl" + Environment.NewLine;
                text += "extension=fileinfo" + Environment.NewLine;
                text += "extension=gd2" + Environment.NewLine;
                text += "extension=gettext" + Environment.NewLine;
                text += "extension=mbstring" + Environment.NewLine;
                text += "extension=exif" + Environment.NewLine;
                text += "extension=mysqli" + Environment.NewLine;
                text += "extension=pdo_mysql" + Environment.NewLine;
                text += "extension=pdo_sqlite" + Environment.NewLine;
                text += "asp_tags=Off" + Environment.NewLine;
                text += "display_startup_errors=On" + Environment.NewLine;
                text += "track_errors=Off" + Environment.NewLine;
                text += "y2k_compliance=On" + Environment.NewLine;
                text += "allow_call_time_pass_reference=Off" + Environment.NewLine;
                text += "safe_mode=Off" + Environment.NewLine;
                text += "safe_mode_gid=Off" + Environment.NewLine;
                text += "safe_mode_allowed_env_vars=PHP_" + Environment.NewLine;
                text += "safe_mode_protected_env_vars=LD_LIBRARY_PATH" + Environment.NewLine;
                text += "error_log=\"" + Environment.CurrentDirectory + "\\dosyalar\\php\\logs\\php_error_log\"" + Environment.NewLine;
                text += "register_globals=Off" + Environment.NewLine;
                text += "register_long_arrays=Off" + Environment.NewLine;
                text += "magic_quotes_gpc=Off" + Environment.NewLine;
                text += "magic_quotes_runtime=Off" + Environment.NewLine;
                text += "magic_quotes_sybase=Off" + Environment.NewLine;
                text += "extension=php_openssl.dll" + Environment.NewLine;
                text += "extension=php_ftp.dll" + Environment.NewLine;
                text += "[CLI Server]" + Environment.NewLine;
                text += "cli_server.color=On" + Environment.NewLine;
                text += "[Date]" + Environment.NewLine;
                text += "[filter]" + Environment.NewLine;
                text += "[iconv]" + Environment.NewLine;
                text += "[imap]" + Environment.NewLine;
                text += "[intl]" + Environment.NewLine;
                text += "[sqlite3]" + Environment.NewLine;
                text += "[Pcre]" + Environment.NewLine;
                text += "[Pdo]" + Environment.NewLine;
                text += "pdo_mysql.default_socket=\"MySQL\"" + Environment.NewLine;
                text += "[Pdo_mysql]" + Environment.NewLine;
                text += "pdo_mysql.default_socket=" + Environment.NewLine;
                text += "[Phar]" + Environment.NewLine;
                text += "[mail function]" + Environment.NewLine;
                text += "SMTP=localhost" + Environment.NewLine;
                text += "smtp_port=25" + Environment.NewLine;
                text += "mail.add_x_header=Off" + Environment.NewLine;
                text += "[ODBC]" + Environment.NewLine;
                text += "odbc.allow_persistent=On" + Environment.NewLine;
                text += "odbc.check_persistent=On" + Environment.NewLine;
                text += "odbc.max_persistent=-1" + Environment.NewLine;
                text += "odbc.max_links=-1" + Environment.NewLine;
                text += "odbc.defaultlrl=4096" + Environment.NewLine;
                text += "odbc.defaultbinmode=1" + Environment.NewLine;
                text += "[Interbase]" + Environment.NewLine;
                text += "ibase.allow_persistent=1" + Environment.NewLine;
                text += "ibase.max_persistent=-1" + Environment.NewLine;
                text += "ibase.max_links=-1" + Environment.NewLine;
                text += "ibase.timestampformat=\"%Y-%m-%d %H:%M:%S\"" + Environment.NewLine;
                text += "ibase.dateformat=\"%Y-%m-%d\"" + Environment.NewLine;
                text += "ibase.timeformat=\"%H:%M:%S\"" + Environment.NewLine;
                text += "[MySQLi]" + Environment.NewLine;
                text += "mysqli.max_persistent=-1" + Environment.NewLine;
                text += "mysqli.allow_persistent=On" + Environment.NewLine;
                text += "mysqli.max_links=-1" + Environment.NewLine;
                text += "mysqli.default_port=3306" + Environment.NewLine;
                text += "mysqli.default_socket=" + Environment.NewLine;
                text += "mysqli.default_host=" + Environment.NewLine;
                text += "mysqli.default_user=" + Environment.NewLine;
                text += "mysqli.default_pw=" + Environment.NewLine;
                text += "mysqli.reconnect=Off" + Environment.NewLine;
                text += "[mysqlnd]" + Environment.NewLine;
                text += "mysqlnd.collect_statistics=On" + Environment.NewLine;
                text += "mysqlnd.collect_memory_statistics=On" + Environment.NewLine;
                text += "[OCI8]" + Environment.NewLine;
                text += "[PostgreSQL]" + Environment.NewLine;
                text += "pgsql.allow_persistent=On" + Environment.NewLine;
                text += "pgsql.auto_reset_persistent=Off" + Environment.NewLine;
                text += "pgsql.max_persistent=-1" + Environment.NewLine;
                text += "pgsql.max_links=-1" + Environment.NewLine;
                text += "pgsql.ignore_notice=0" + Environment.NewLine;
                text += "pgsql.log_notice=0" + Environment.NewLine;
                text += "[bcmath]" + Environment.NewLine;
                text += "bcmath.scale=0" + Environment.NewLine;
                text += "[browscap]" + Environment.NewLine;
                text += "browscap=\"" + Environment.CurrentDirectory + "\\dosyalar\\php\\extras\\browscap.ini\"" + Environment.NewLine;
                text += "[Session]" + Environment.NewLine;
                text += "session.save_handler=files" + Environment.NewLine;
                text += "session.save_path=\"" + Environment.CurrentDirectory + "\\dosyalar\\tmp\"" + Environment.NewLine;
                text += "session.use_strict_mode=0" + Environment.NewLine;
                text += "session.use_cookies=1" + Environment.NewLine;
                text += "session.use_only_cookies=1" + Environment.NewLine;
                text += "session.name=PHPSESSID" + Environment.NewLine;
                text += "session.auto_start=0" + Environment.NewLine;
                text += "session.cookie_lifetime=0" + Environment.NewLine;
                text += "session.cookie_path=/" + Environment.NewLine;
                text += "session.cookie_domain=" + Environment.NewLine;
                text += "session.cookie_httponly=" + Environment.NewLine;
                text += "session.cookie_samesite=" + Environment.NewLine;
                text += "session.serialize_handler=php" + Environment.NewLine;
                text += "session.gc_probability=1" + Environment.NewLine;
                text += "session.gc_divisor=1000" + Environment.NewLine;
                text += "session.gc_maxlifetime=1440" + Environment.NewLine;
                text += "session.referer_check=" + Environment.NewLine;
                text += "session.cache_limiter=nocache" + Environment.NewLine;
                text += "session.cache_expire=180" + Environment.NewLine;
                text += "session.use_trans_sid=0" + Environment.NewLine;
                text += "session.sid_length=26" + Environment.NewLine;
                text += "session.trans_sid_tags=\"a=href,area=href,frame=src,form=\"" + Environment.NewLine;
                text += "session.sid_bits_per_character=5" + Environment.NewLine;
                text += "[Assertion]" + Environment.NewLine;
                text += "zend.assertions=1" + Environment.NewLine;
                text += "[COM]" + Environment.NewLine;
                text += "[mbstring]" + Environment.NewLine;
                text += "[gd]" + Environment.NewLine;
                text += "[exif]" + Environment.NewLine;
                text += "[Tidy]" + Environment.NewLine;
                text += "tidy.clean_output=Off" + Environment.NewLine;
                text += "[soap]" + Environment.NewLine;
                text += "soap.wsdl_cache_enabled=1" + Environment.NewLine;
                text += "soap.wsdl_cache_dir=\"/tmp\"" + Environment.NewLine;
                text += "soap.wsdl_cache_ttl=86400" + Environment.NewLine;
                text += "soap.wsdl_cache_limit=5" + Environment.NewLine;
                text += "[sysvshm]" + Environment.NewLine;
                text += "[ldap]" + Environment.NewLine;
                text += "ldap.max_links=-1" + Environment.NewLine;
                text += "[dba]" + Environment.NewLine;
                text += "[opcache]" + Environment.NewLine;
                text += "[curl]" + Environment.NewLine;
                text += "curl.cainfo=\"" + Environment.CurrentDirectory + "\\dosyalar\\apache\\bin\\curl-ca-bundle.crt\"" + Environment.NewLine;
                text += "[openssl]" + Environment.NewLine;
                text += "openssl.cafile=\"" + Environment.CurrentDirectory + "\\dosyalar\\apache\\bin\\curl-ca-bundle.crt\"" + Environment.NewLine;
                text += "[Syslog]" + Environment.NewLine;
                text += "define_syslog_variables=Off" + Environment.NewLine;
                text += "[Session]" + Environment.NewLine;
                text += "define_syslog_variables=Off" + Environment.NewLine;
                text += "[Date]" + Environment.NewLine;
                text += "date.timezone=Europe/Berlin" + Environment.NewLine;
                text += "[MySQL]" + Environment.NewLine;
                text += "mysql.allow_local_infile=On" + Environment.NewLine;
                text += "mysql.allow_persistent=On" + Environment.NewLine;
                text += "mysql.cache_size=2000" + Environment.NewLine;
                text += "mysql.max_persistent=-1" + Environment.NewLine;
                text += "mysql.max_link=-1" + Environment.NewLine;
                text += "mysql.default_port=3306" + Environment.NewLine;
                text += "mysql.default_socket=\"MySQL\"" + Environment.NewLine;
                text += "mysql.connect_timeout=3" + Environment.NewLine;
                text += "mysql.trace_mode=Off" + Environment.NewLine;
                text += "[Sybase-CT]" + Environment.NewLine;
                text += "sybct.allow_persistent=On" + Environment.NewLine;
                text += "sybct.max_persistent=-1" + Environment.NewLine;
                text += "sybct.max_links=-1" + Environment.NewLine;
                text += "sybct.min_server_severity=10" + Environment.NewLine;
                text += "sybct.min_client_severity=10" + Environment.NewLine;
                text += "[MSSQL]" + Environment.NewLine;
                text += "mssql.allow_persistent=On" + Environment.NewLine;
                text += "mssql.max_persistent=-1" + Environment.NewLine;
                text += "mssql.max_links=-1" + Environment.NewLine;
                text += "mssql.min_error_severity=10" + Environment.NewLine;
                text += "mssql.min_message_severity=10" + Environment.NewLine;
                text += "mssql.compatability_mode=Off" + Environment.NewLine;
                text += "mssql.secure_connection=Off";
                File.WriteAllText(yol, text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        public void my_ini_olustur()
        {
            try
            {
                string yol = Environment.CurrentDirectory + @"\dosyalar\mysql\bin\my.ini";
                string text = "";
                text += "[client]" + Environment.NewLine;
                text += "#password=your_password" + Environment.NewLine;
                text += "port=3307" + Environment.NewLine;
                text += "socket=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql/mysql.sock\"" + Environment.NewLine;
                text += "default-character-set=utf8mb4" + Environment.NewLine;
                text += "[mysqld]" + Environment.NewLine;
                text += "port=3307" + Environment.NewLine;
                text += "socket=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql/mysql.sock\"" + Environment.NewLine;
                text += "basedir=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql\"" + Environment.NewLine;
                text += "tmpdir=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/tmp\"" + Environment.NewLine;
                text += "datadir=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql/data\"" + Environment.NewLine;
                text += "pid_file=\"mysql.pid\"" + Environment.NewLine;
                text += "# enable-named-pipe" + Environment.NewLine;
                text += "key_buffer_size=16M" + Environment.NewLine;
                text += "max_allowed_packet=1M" + Environment.NewLine;
                text += "sort_buffer_size=512K" + Environment.NewLine;
                text += "net_buffer_length=8K" + Environment.NewLine;
                text += "read_buffer_size=256K" + Environment.NewLine;
                text += "read_rnd_buffer_size=512K" + Environment.NewLine;
                text += "myisam_sort_buffer_size=975M" + Environment.NewLine;
                text += "log_error=\"mysql_error.log\"" + Environment.NewLine;
                text += "# bind-address=\"127.0.0.1\" " + Environment.NewLine;
                text += "plugin_dir=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql/lib/plugin/\"" + Environment.NewLine;
                text += "server-id=1" + Environment.NewLine;
                text += "innodb_data_home_dir=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql/data\"" + Environment.NewLine;
                text += "innodb_data_file_path=ibdata1:10M:autoextend" + Environment.NewLine;
                text += "innodb_log_group_home_dir=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql/data\"" + Environment.NewLine;
                text += "innodb_buffer_pool_size=16M" + Environment.NewLine;
                text += "innodb_log_file_size=5M" + Environment.NewLine;
                text += "innodb_log_buffer_size=8M" + Environment.NewLine;
                text += "innodb_flush_log_at_trx_commit=1" + Environment.NewLine;
                text += "innodb_lock_wait_timeout=50" + Environment.NewLine;
                text += "sql_mode=NO_ZERO_IN_DATE,NO_ZERO_DATE,NO_ENGINE_SUBSTITUTION" + Environment.NewLine;
                text += "log_bin_trust_function_creators=1" + Environment.NewLine;
                text += "character-set-server=utf8mb4" + Environment.NewLine;
                text += "collation-server=utf8mb4_general_ci" + Environment.NewLine;
                text += "[mysqldump]" + Environment.NewLine;
                text += "max_allowed_packet=16M" + Environment.NewLine;
                text += "[mysql]" + Environment.NewLine;
                text += "[isamchk]" + Environment.NewLine;
                text += "key_buffer=20M" + Environment.NewLine;
                text += "sort_buffer_size=20M" + Environment.NewLine;
                text += "read_buffer=2M" + Environment.NewLine;
                text += "write_buffer=2M" + Environment.NewLine;
                text += "[myisamchk]" + Environment.NewLine;
                text += "key_buffer=20M" + Environment.NewLine;
                text += "sort_buffer_size=20M" + Environment.NewLine;
                text += "read_buffer=2M" + Environment.NewLine;
                text += "write_buffer=2M" + Environment.NewLine;
                text += "[mysqlhotcopy]";
                File.WriteAllText(yol, text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        public void my_ini2_olustur()
        {
            try
            {
                string yol = Environment.CurrentDirectory + @"\dosyalar\mysql\data\my.ini";
                string text = "";
                text += "[client]" + Environment.NewLine;
                text += "#password=your_password" + Environment.NewLine;
                text += "port=3307" + Environment.NewLine;
                text += "socket=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql/mysql.sock\"" + Environment.NewLine;
                text += "default-character-set=utf8mb4" + Environment.NewLine;
                text += "[mysqld]" + Environment.NewLine;
                text += "port=3307" + Environment.NewLine;
                text += "socket=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql/mysql.sock\"" + Environment.NewLine;
                text += "basedir=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql\"" + Environment.NewLine;
                text += "tmpdir=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/tmp\"" + Environment.NewLine;
                text += "datadir=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql/data\"" + Environment.NewLine;
                text += "pid_file=\"mysql.pid\"" + Environment.NewLine;
                text += "# enable-named-pipe" + Environment.NewLine;
                text += "key_buffer_size=16M" + Environment.NewLine;
                text += "max_allowed_packet=1M" + Environment.NewLine;
                text += "sort_buffer_size=512K" + Environment.NewLine;
                text += "net_buffer_length=8K" + Environment.NewLine;
                text += "read_buffer_size=256K" + Environment.NewLine;
                text += "read_rnd_buffer_size=512K" + Environment.NewLine;
                text += "myisam_sort_buffer_size=975M" + Environment.NewLine;
                text += "log_error=\"mysql_error.log\"" + Environment.NewLine;
                text += "# bind-address=\"127.0.0.1\" " + Environment.NewLine;
                text += "plugin_dir=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql/lib/plugin/\"" + Environment.NewLine;
                text += "server-id=1" + Environment.NewLine;
                text += "innodb_data_home_dir=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql/data\"" + Environment.NewLine;
                text += "innodb_data_file_path=ibdata1:10M:autoextend" + Environment.NewLine;
                text += "innodb_log_group_home_dir=\"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/mysql/data\"" + Environment.NewLine;
                text += "innodb_buffer_pool_size=16M" + Environment.NewLine;
                text += "innodb_log_file_size=5M" + Environment.NewLine;
                text += "innodb_log_buffer_size=8M" + Environment.NewLine;
                text += "innodb_flush_log_at_trx_commit=1" + Environment.NewLine;
                text += "innodb_lock_wait_timeout=50" + Environment.NewLine;
                text += "sql_mode=NO_ZERO_IN_DATE,NO_ZERO_DATE,NO_ENGINE_SUBSTITUTION" + Environment.NewLine;
                text += "log_bin_trust_function_creators=1" + Environment.NewLine;
                text += "character-set-server=utf8mb4" + Environment.NewLine;
                text += "collation-server=utf8mb4_general_ci" + Environment.NewLine;
                text += "[mysqldump]" + Environment.NewLine;
                text += "max_allowed_packet=16M" + Environment.NewLine;
                text += "[mysql]" + Environment.NewLine;
                text += "[isamchk]" + Environment.NewLine;
                text += "key_buffer=20M" + Environment.NewLine;
                text += "sort_buffer_size=20M" + Environment.NewLine;
                text += "read_buffer=2M" + Environment.NewLine;
                text += "write_buffer=2M" + Environment.NewLine;
                text += "[myisamchk]" + Environment.NewLine;
                text += "key_buffer=20M" + Environment.NewLine;
                text += "sort_buffer_size=20M" + Environment.NewLine;
                text += "read_buffer=2M" + Environment.NewLine;
                text += "write_buffer=2M" + Environment.NewLine;
                text += "[mysqlhotcopy]";
                File.WriteAllText(yol, text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }
        public void httpd_autoindex_conf_olustur()
        {
            try
            {
                string yol = Environment.CurrentDirectory + @"\dosyalar\apache\conf\extra\httpd-autoindex.conf";
                string text = "";
                text += "<IfModule autoindex_module>" + Environment.NewLine;
                text += "<IfModule alias_module>" + Environment.NewLine;
                text += "IndexOptions FancyIndexing HTMLTable VersionSort" + Environment.NewLine;
                text += "Alias /icons/ \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache/icons/\"" + Environment.NewLine;
                text += "<Directory \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache/icons\">" + Environment.NewLine;
                text += "    Options Indexes MultiViews" + Environment.NewLine;
                text += "    AllowOverride None" + Environment.NewLine;
                text += "    Require all granted" + Environment.NewLine;
                text += "</Directory>" + Environment.NewLine;
                text += "AddIconByEncoding (CMP,/icons/compressed.gif) x-compress x-gzip" + Environment.NewLine;
                text += "AddIconByType (TXT,/icons/text.gif) text/*" + Environment.NewLine;
                text += "AddIconByType (IMG,/icons/image2.gif) image/*" + Environment.NewLine;
                text += "AddIconByType (SND,/icons/sound2.gif) audio/*" + Environment.NewLine;
                text += "AddIconByType (VID,/icons/movie.gif) video/*" + Environment.NewLine;
                text += "AddIcon /icons/binary.gif .bin .exe" + Environment.NewLine;
                text += "AddIcon /icons/binhex.gif .hqx" + Environment.NewLine;
                text += "AddIcon /icons/tar.gif .tar" + Environment.NewLine;
                text += "AddIcon /icons/world2.gif .wrl .wrl.gz .vrml .vrm .iv" + Environment.NewLine;
                text += "AddIcon /icons/compressed.gif .Z .z .tgz .gz .zip" + Environment.NewLine;
                text += "AddIcon /icons/a.gif .ps .ai .eps" + Environment.NewLine;
                text += "AddIcon /icons/layout.gif .html .shtml .htm .pdf" + Environment.NewLine;
                text += "AddIcon /icons/text.gif .txt" + Environment.NewLine;
                text += "AddIcon /icons/c.gif .c" + Environment.NewLine;
                text += "AddIcon /icons/p.gif .pl .py" + Environment.NewLine;
                text += "AddIcon /icons/f.gif .for" + Environment.NewLine;
                text += "AddIcon /icons/dvi.gif .dvi" + Environment.NewLine;
                text += "AddIcon /icons/uuencoded.gif .uu" + Environment.NewLine;
                text += "AddIcon /icons/script.gif .conf .sh .shar .csh .ksh .tcl" + Environment.NewLine;
                text += "AddIcon /icons/tex.gif .tex" + Environment.NewLine;
                text += "AddIcon /icons/bomb.gif core" + Environment.NewLine;
                text += "AddIcon /icons/back.gif .." + Environment.NewLine;
                text += "AddIcon /icons/hand.right.gif README" + Environment.NewLine;
                text += "AddIcon /icons/folder.gif ^^DIRECTORY^^" + Environment.NewLine;
                text += "AddIcon /icons/blank.gif ^^BLANKICON^^" + Environment.NewLine;
                text += "DefaultIcon /icons/unknown.gif" + Environment.NewLine;
                text += "ReadmeName README.html" + Environment.NewLine;
                text += "HeaderName HEADER.html" + Environment.NewLine;
                text += "IndexIgnore .??* *~ *# HEADER* README* RCS CVS *,v *,t" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "</IfModule>";
                File.WriteAllText(yol, text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        public void httpd_dav_conf_olustur()
        {
            try
            {
                string yol = Environment.CurrentDirectory + @"\dosyalar\apache\conf\extra\httpd-dav.conf";
                string text = "";
                text += "<IfModule dav_module>" + Environment.NewLine;
                text += "<IfModule dav_fs_module>" + Environment.NewLine;
                text += "<IfModule setenvif_module>" + Environment.NewLine;
                text += "<IfModule alias_module>" + Environment.NewLine;
                text += "<IfModule auth_digest_module>" + Environment.NewLine;
                text += "<IfModule authn_file_module>#" + Environment.NewLine;
                text += "DavLockDB \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache/logs/Dav.Lock\"" + Environment.NewLine;
                text += "Alias /webdav \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/webdav/\"" + Environment.NewLine;
                text += "<Directory \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/webdav\">" + Environment.NewLine;
                text += "Require all granted" + Environment.NewLine;
                text += "    Dav On" + Environment.NewLine;
                text += "    AuthType Digest" + Environment.NewLine;
                text += "    AuthName \"XAMPP with WebDAV\"" + Environment.NewLine;
                text += "    AuthUserFile \"${SRVROOT}/user.passwd\"" + Environment.NewLine;
                text += "    AuthDigestProvider file" + Environment.NewLine;
                text += "    <LimitExcept GET OPTIONS>" + Environment.NewLine;
                text += "        require valid-user" + Environment.NewLine;
                text += "    </LimitExcept>" + Environment.NewLine;
                text += "</Directory>" + Environment.NewLine;
                text += "BrowserMatch \"Microsoft Data Access Internet Publishing Provider\" redirect-carefully" + Environment.NewLine;
                text += "BrowserMatch \"MS FrontPage\" redirect-carefully" + Environment.NewLine;
                text += "BrowserMatch \"^WebDrive\" redirect-carefully" + Environment.NewLine;
                text += "BrowserMatch \"^WebDAVFS/1.[01234]\" redirect-carefully" + Environment.NewLine;
                text += "BrowserMatch \"^gnome-vfs/1.0\" redirect-carefully" + Environment.NewLine;
                text += "BrowserMatch \"^XML Spy\" redirect-carefully" + Environment.NewLine;
                text += "BrowserMatch \"^Dreamweaver-WebDAV-SCM1\" redirect-carefully" + Environment.NewLine;
                text += "BrowserMatch \"Konqueror/4\" redirect-carefully" + Environment.NewLine;
                text += "BrowserMatch \"MSIE\" AuthDigestEnableQueryStringHack=On" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "</IfModule>";
                File.WriteAllText(yol, text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        public void httpd_manual_conf_olustur()
        {
            try
            {
                string yol = Environment.CurrentDirectory + @"\dosyalar\apache\conf\extra\httpd-manual.conf";
                string text = "";
                text += "AliasMatch ^/manual(?:/(?:da|de|en|es|fr|ja|ko|pt-br|ru|tr|zh-cn))?(/.*)?$ \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache/manual$1\"" + Environment.NewLine;
                text += "<Directory \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache/manual\">" + Environment.NewLine;
                text += "    Options Indexes" + Environment.NewLine;
                text += "    AllowOverride None" + Environment.NewLine;
                text += "    Require all granted" + Environment.NewLine;
                text += "    <Files *.html>" + Environment.NewLine;
                text += "        SetHandler type-map" + Environment.NewLine;
                text += "    </Files>" + Environment.NewLine;
                text += "    RemoveType tr" + Environment.NewLine;
                text += "    AddLanguage da .da" + Environment.NewLine;
                text += "    SetEnvIf Request_URI ^/manual/(da|de|en|es|fr|ja|ko|pt-br|ru|tr|zh-cn)/ prefer-language=$1" + Environment.NewLine;
                text += "    RedirectMatch 301 ^/manual(?:/(da|de|en|es|fr|ja|ko|pt-br|ru|tr|zh-cn)){2,}(/.*)?$ /manual/$1$2" + Environment.NewLine;
                text += "    LanguagePriority   en  fr  ko ja tr es de zh-cn pt-br da ru" + Environment.NewLine;
                text += "    ForceLanguagePriority Prefer Fallback" + Environment.NewLine;
                text += "</Directory>";
                File.WriteAllText(yol, text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        public void httpd_multilang_errordoc_conf_olustur()
        {
            try
            {
                string yol = Environment.CurrentDirectory + @"\dosyalar\apache\conf\extra\httpd-multilang-errordoc.conf";
                string text = "";
                text += "<IfModule alias_module>" + Environment.NewLine;
                text += "<IfModule include_module>" + Environment.NewLine;
                text += "<IfModule negotiation_module>" + Environment.NewLine;
                text += "Alias /error/ \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache/error/\"" + Environment.NewLine;
                text += "<Directory \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache/error\">" + Environment.NewLine;
                text += "    AllowOverride None" + Environment.NewLine;
                text += "    Options IncludesNoExec" + Environment.NewLine;
                text += "    AddOutputFilter Includes html" + Environment.NewLine;
                text += "    AddHandler type-map var" + Environment.NewLine;
                text += "    Require all granted" + Environment.NewLine;
                text += "    LanguagePriority en cs de es fr it ja ko nl pl pt-br ro sv tr" + Environment.NewLine;
                text += "    ForceLanguagePriority Prefer Fallback" + Environment.NewLine;
                text += "</Directory>" + Environment.NewLine;
                text += "ErrorDocument 400 /error/HTTP_BAD_REQUEST.html.var" + Environment.NewLine;
                text += "ErrorDocument 401 /error/HTTP_UNAUTHORIZED.html.var" + Environment.NewLine;
                text += "ErrorDocument 403 /error/HTTP_FORBIDDEN.html.var" + Environment.NewLine;
                text += "ErrorDocument 404 /error/HTTP_NOT_FOUND.html.var" + Environment.NewLine;
                text += "ErrorDocument 405 /error/HTTP_METHOD_NOT_ALLOWED.html.var" + Environment.NewLine;
                text += "ErrorDocument 408 /error/HTTP_REQUEST_TIME_OUT.html.var" + Environment.NewLine;
                text += "ErrorDocument 410 /error/HTTP_GONE.html.var" + Environment.NewLine;
                text += "ErrorDocument 411 /error/HTTP_LENGTH_REQUIRED.html.var" + Environment.NewLine;
                text += "ErrorDocument 412 /error/HTTP_PRECONDITION_FAILED.html.var" + Environment.NewLine;
                text += "ErrorDocument 413 /error/HTTP_REQUEST_ENTITY_TOO_LARGE.html.var" + Environment.NewLine;
                text += "ErrorDocument 414 /error/HTTP_REQUEST_URI_TOO_LARGE.html.var" + Environment.NewLine;
                text += "ErrorDocument 415 /error/HTTP_UNSUPPORTED_MEDIA_TYPE.html.var" + Environment.NewLine;
                text += "ErrorDocument 500 /error/HTTP_INTERNAL_SERVER_ERROR.html.var" + Environment.NewLine;
                text += "ErrorDocument 501 /error/HTTP_NOT_IMPLEMENTED.html.var" + Environment.NewLine;
                text += "ErrorDocument 502 /error/HTTP_BAD_GATEWAY.html.var" + Environment.NewLine;
                text += "ErrorDocument 503 /error/HTTP_SERVICE_UNAVAILABLE.html.var" + Environment.NewLine;
                text += "ErrorDocument 506 /error/HTTP_VARIANT_ALSO_VARIES.html.var" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "</IfModule>";
                File.WriteAllText(yol, text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        public void httpd_xampp_conf_olustur()
        {
            try
            {

                string yol = Environment.CurrentDirectory + @"\dosyalar\apache\conf\extra\httpd-xampp.conf";
                string text = "";
                text += "<IfModule env_module>" + Environment.NewLine;
                text += "    SetEnv MIBDIRS \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/php/extras/mibs\"" + Environment.NewLine;
                text += "    SetEnv MYSQL_HOME \"\\\\xampp\\\\mysql\\\\bin\"" + Environment.NewLine;
                text += "    SetEnv OPENSSL_CONF \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/apache/bin/openssl.cnf\"" + Environment.NewLine;
                text += "    SetEnv PHP_PEAR_SYSCONF_DIR \"\\\\xampp\\\\php\"" + Environment.NewLine;
                text += "    SetEnv PHPRC \"\\\\xampp\\\\php\"" + Environment.NewLine;
                text += "    SetEnv TMP \"\\\\xampp\\\\tmp\"" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "LoadFile \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/php/php7ts.dll\"" + Environment.NewLine;
                text += "LoadFile \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/php/libpq.dll\"" + Environment.NewLine;
                text += "LoadModule php7_module \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/php/php7apache2_4.dll\"" + Environment.NewLine;
                text += "<FilesMatch \"\\.php$\">" + Environment.NewLine;
                text += "    SetHandler application/x-httpd-php" + Environment.NewLine;
                text += "</FilesMatch>" + Environment.NewLine;
                text += "<FilesMatch \"\\.phps$\">" + Environment.NewLine;
                text += "    SetHandler application/x-httpd-php-source" + Environment.NewLine;
                text += "</FilesMatch>" + Environment.NewLine;
                text += "<IfModule php7_module>" + Environment.NewLine;
                text += "    PHPINIDir \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/php\"" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "<IfModule mime_module>" + Environment.NewLine;
                text += "    AddType text/html .php .phps" + Environment.NewLine;
                text += "</IfModule>" + Environment.NewLine;
                text += "ScriptAlias /php-cgi/ \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/php/\"" + Environment.NewLine;
                text += "<Directory \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/php\">" + Environment.NewLine;
                text += "    AllowOverride None" + Environment.NewLine;
                text += "    Options None" + Environment.NewLine;
                text += "    Require all denied" + Environment.NewLine;
                text += "    <Files \"php-cgi.exe\">" + Environment.NewLine;
                text += "          Require all granted" + Environment.NewLine;
                text += "    </Files>" + Environment.NewLine;
                text += "</Directory>" + Environment.NewLine;
                text += "<Directory \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/cgi-bin\">" + Environment.NewLine;
                text += "    <FilesMatch \"\\.php$\">" + Environment.NewLine;
                text += "        SetHandler cgi-script" + Environment.NewLine;
                text += "    </FilesMatch>" + Environment.NewLine;
                text += "    <FilesMatch \"\\.phps$\">" + Environment.NewLine;
                text += "        SetHandler None" + Environment.NewLine;
                text += "    </FilesMatch>" + Environment.NewLine;
                text += "</Directory>" + Environment.NewLine;
                text += "<Directory \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/htdocs/xampp\">" + Environment.NewLine;
                text += "    <IfModule php7_module>" + Environment.NewLine;
                text += "    	<Files \"status.php\">" + Environment.NewLine;
                text += "    		php_admin_flag safe_mode off" + Environment.NewLine;
                text += "    	</Files>" + Environment.NewLine;
                text += "    </IfModule>" + Environment.NewLine;
                text += "    AllowOverride AuthConfig" + Environment.NewLine;
                text += "</Directory>" + Environment.NewLine;
                text += "<IfModule alias_module>" + Environment.NewLine;
                text += "    Alias /licenses \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/licenses/\"" + Environment.NewLine;
                text += "    <Directory \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/licenses\">" + Environment.NewLine;
                text += "        Options +Indexes" + Environment.NewLine;
                text += "        <IfModule autoindex_color_module>" + Environment.NewLine;
                text += "            DirectoryIndexTextColor  \"#000000\"" + Environment.NewLine;
                text += "            DirectoryIndexBGColor \"#f8e8a0\"" + Environment.NewLine;
                text += "            DirectoryIndexLinkColor \"#bb3902\"" + Environment.NewLine;
                text += "            DirectoryIndexVLinkColor \"#bb3902\"" + Environment.NewLine;
                text += "            DirectoryIndexALinkColor \"#bb3902\"" + Environment.NewLine;
                text += "        </IfModule>" + Environment.NewLine;
                text += "        Require local" + Environment.NewLine;
                text += "        ErrorDocument 403 /error/XAMPP_FORBIDDEN.html.var" + Environment.NewLine;
                text += "   </Directory>" + Environment.NewLine;
                text += "    Alias /phpmyadmin \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/phpMyAdmin/\"" + Environment.NewLine;
                text += "    <Directory \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/phpMyAdmin\">" + Environment.NewLine;
                text += "        AllowOverride AuthConfig" + Environment.NewLine;
                text += "        Require local" + Environment.NewLine;
                text += "        ErrorDocument 403 /error/XAMPP_FORBIDDEN.html.var" + Environment.NewLine;
                text += "    </Directory>" + Environment.NewLine;
                text += "    Alias /webalizer \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/webalizer/\"" + Environment.NewLine;
                text += "    <Directory \"" + Environment.CurrentDirectory.Replace('\\', '/') + "/dosyalar/webalizer\">" + Environment.NewLine;
                text += "        <IfModule php7_module>" + Environment.NewLine;
                text += "    		<Files \"webalizer.php\">" + Environment.NewLine;
                text += "    			php_admin_flag safe_mode off" + Environment.NewLine;
                text += "    		</Files>" + Environment.NewLine;
                text += "        </IfModule>" + Environment.NewLine;
                text += "        AllowOverride AuthConfig" + Environment.NewLine;
                text += "        Require local" + Environment.NewLine;
                text += "        ErrorDocument 403 /error/XAMPP_FORBIDDEN.html.var" + Environment.NewLine;
                text += "    </Directory>" + Environment.NewLine;
                text += "</IfModule>";
                File.WriteAllText(yol, text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        public void multi_master_info()
        {
            try
            {

                string multi_master_info = Environment.CurrentDirectory + @"\dosyalar\mysql\data\multi-master.info";
                File.WriteAllText(multi_master_info, "");
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }
        private void klasorolustur()
        {
            string tmp = Environment.CurrentDirectory + "\\dosyalar\\tmp";
            try
            {
                if (File.Exists(tmp) == false)
                {
                    Directory.CreateDirectory(tmp);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }
        private void dispatcherTimer_Tick(object sender, EventArgs e)
        {
            if (backgroundWorker1.IsBusy != true)
            {
                backgroundWorker1.RunWorkerAsync();
            }
            if (backgroundWorker2.IsBusy != true)
            {
                backgroundWorker2.RunWorkerAsync();
            }
            if (backgroundWorker3.IsBusy != true)
            {
                backgroundWorker3.RunWorkerAsync();
            }
        }

        private void backgroundWorker2_DoWork(object sender, DoWorkEventArgs e)
        {
            bool kontrol = false;

            foreach (var process in Process.GetProcessesByName("httpd"))
            {
                kontrol = true;
            }
            if (kontrol == false)
            {
                try
                {
                    string yol = Environment.CurrentDirectory + @"\dosyalar\apache\bin\httpd.exe";
                    ProcessStartInfo process = new ProcessStartInfo();
                    process.UseShellExecute = true;
                    process.ErrorDialog = true;
                    process.FileName = Path.GetFileName(yol);
                    process.WorkingDirectory = Path.GetDirectoryName(yol);
                    process.WindowStyle = ProcessWindowStyle.Hidden;
                    //process.Verb = "runas";
                    //process.Arguments = "guncelleodm";
                    Process processs = Process.Start(process);
                    processs.WaitForExit();
                }
                catch (Win32Exception ex)
                {
                    MessageBox.Show(ex.ToString());
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.ToString());
                }
            }
        }

        private void backgroundWorker2_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
        }

        private void backgroundWorker2_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
        }

        private void backgroundWorker3_DoWork(object sender, DoWorkEventArgs e)
        {
            bool kontrol = false;

            foreach (var process in Process.GetProcessesByName("mysqld"))
            {
                kontrol = true;
            }
            if (kontrol == false)
            {
                try
                {
                    string yol = Environment.CurrentDirectory + @"\dosyalar\mysql\bin\mysqld";
                    ProcessStartInfo process = new ProcessStartInfo();
                    process.UseShellExecute = true;
                    process.ErrorDialog = true;
                    process.FileName = Path.GetFileName(yol);
                    process.WorkingDirectory = Path.GetDirectoryName(yol);
                    process.WindowStyle = ProcessWindowStyle.Hidden;
                    //process.Verb = "runas";
                    //process.Arguments = "--defaults-file=mysql\bin\\my.ini --standalone";
                    Process processs = Process.Start(process);
                    processs.WaitForExit();
                }
                catch (Win32Exception ex)
                {
                    MessageBox.Show(ex.ToString());
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.ToString());
                }
            }
        }

        private void backgroundWorker3_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {

        }

        private void backgroundWorker3_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {

        }
        private void backgroundWorker1_DoWork(object sender, DoWorkEventArgs e)
        {
            WqlEventQuery removeQuery = new WqlEventQuery("SELECT * FROM __InstanceDeletionEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_USBHub'");
            ManagementEventWatcher removeWatcher = new ManagementEventWatcher(removeQuery);
            removeWatcher.EventArrived += new EventArrivedEventHandler(DeviceRemovedEvent);
            removeWatcher.Start();

            apacherenk = false;
            mysqlrenk = false;
            Application.Current.Dispatcher.Invoke((Action)(() =>
            {
                foreach (var process in Process.GetProcessesByName("httpd"))
                {
                    apacherenk = true;
                }
                foreach (var process in Process.GetProcessesByName("mysqld"))
                {
                    mysqlrenk = true;
                }
            }));
        }

        private void backgroundWorker1_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {

        }

        private void backgroundWorker1_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            Application.Current.Dispatcher.Invoke((Action)(() =>
            {
                if (apacherenk == false)
                {
                    ellipseapache.Fill = Brushes.Red;
                    ellipseapache.ToolTip = "Apache Server Çalışmıyor(Port:88)";
                }

                else
                {
                    ellipseapache.ToolTip = "Apache Server Çalışıyor(Port:88)";
                    ellipseapache.Fill = Brushes.Green;
                }
                if (mysqlrenk == false)
                {
                    ellipsemysql.Fill = Brushes.Red;
                    ellipsemysql.ToolTip = "Mysql Server Çalışmıyor(Port:3307)";
                }
                else
                {
                    ellipsemysql.Fill = Brushes.Green;
                    ellipsemysql.ToolTip = "Mysql Server Çalışıyor(Port:3307)";
                }
            }));
        }
        private void Window_Closed(object sender, EventArgs e)
        {
            foreach (var process in Process.GetProcessesByName("mysqld"))
            {
                process.Kill();
            }
            foreach (var process in Process.GetProcessesByName("httpd"))
            {
                process.Kill();
            }
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            UsbSN serino = new UsbSN();
            if (serino.Usbserinokontrol() == true)
            {
                try
                {
                    httpd_conf_olustur();
                    httpd_ssl_conf_olustur();
                    config_inc_php_olustur();
                    php_ini_olustur();
                    my_ini_olustur();
                    my_ini2_olustur();
                    httpd_autoindex_conf_olustur();
                    httpd_dav_conf_olustur();
                    httpd_manual_conf_olustur();
                    httpd_multilang_errordoc_conf_olustur();
                    httpd_xampp_conf_olustur();
                    multi_master_info();
                    klasorolustur();
                    webbrowser.Navigate("http://localhost:88/index.php");
                    dispatcherTimer.Start();
                    File.SetAttributes(Environment.CurrentDirectory + @"\dosyalar", FileAttributes.Hidden | FileAttributes.System);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(ex.ToString());
                }
            }
            else
            {
                animasyon.mesaj.Text = "USB Kopyalama Hatası.\nLütfen orjinal USB'den çalıştırınız.";
                webbrowser.Visibility = Visibility.Hidden;
            }
        }

        private void kapat_png_MouseUp(object sender, MouseButtonEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private void kapat_png_TouchUp(object sender, TouchEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private void webbrowser_Unloaded(object sender, RoutedEventArgs e)
        {
            webbrowser.Navigate("http://localhost:88/index.php");
        }

        int sayac = 0;
        private void webbrowser_LoadCompleted(object sender, NavigationEventArgs e)
        {
            sayac++;
            IHTMLDocument2 dom = (IHTMLDocument2)webbrowser.Document;
            if (dom.title.ToString() != "netfenflash@gmail.com")
            {
                webbrowser.Navigate("http://localhost:88/index.php");
            }
            else
            {
                webbrowser.Visibility = Visibility.Visible;
            }
            animasyon.mesaj.Text = sayac.ToString();
            //webbrowser.Visibility = Visibility.Visible;

        }

        private void DeviceInsertedEvent(object sender, EventArrivedEventArgs e)
        {
            ManagementBaseObject instance = (ManagementBaseObject)e.NewEvent["TargetInstance"];
            foreach (var property in instance.Properties)
            {
                Console.WriteLine(property.Name + " = " + property.Value);
            }
        }

        private void DeviceRemovedEvent(object sender, EventArrivedEventArgs e)
        {
            UsbSN serino = new UsbSN();
            if (serino.Usbserinokontrol() != true)
            {
                Process.GetCurrentProcess().Kill();
            }
        }
    }
}
