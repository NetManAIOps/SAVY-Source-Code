package com.netman.yukawa.safeap;

import android.Manifest;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.net.DhcpInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Message;
import android.provider.Settings;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.text.format.Formatter;
import android.util.Log;
import android.view.View;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.zip.GZIPInputStream;

/*
    btn_f indicates the State of the FSM
    0: init
    1: Wi-Fi info displayed. IP confirm, Mode confirm
    2: Nmap running
    3: Nmap done
    4: Report sent
 */


public class MainActivity_backup extends AppCompatActivity {
    private final int EXPIRED = -1;
    private final int THREAD_ERROR_AKB = 0;
    private final int THREAD_ERROR_CURL = 1;
    private final int SCAN_UI_DONE = 2;
    private final int CURL_UI_DONE = 3;
    private final int AKB_UI_DONE = 4;
    private final int AKB_UI_FAILED = 5;
    private final int SETUP_FINISHED = 6;
    private final int SEND_FAILED = 7;
    private final int SEND_DONE = 8;
    private final int PIC_DONE = 9;

    private TextView myTextView;
    private TextView nmapRes;
    private Button myButton;
    private String ip;
    private String ssid;
    private String bssid;
    private String gatewayIP;
    private String model;
    private String address;

    private WebView webView;

    private Thread tcurl;
    private Thread tnmap;
    private Thread takb;

    private int salt;//For Thread Check. Only the thread with the same salt value will be accpeted. Reset will cause salt value change.

    /* The state of the FSA
        0   start           startNmap()
        1   model probing   startNmap()   yes -> 4; no -> 2
        2   nmap ready      startNmap()
        3   nmap running    startNmap()
        4   nmap done       startNmap()
    */

    private final int FSA_START = 0;
    private final int FSA_MODEL = 1;
    private final int FSA_NMAP_READY = 2;
    private final int FSA_NMAP_RUNNING = 3;
    private final int FSA_NMAP_DONE = 4;
    private final int FSA_MODEL_RUNING = 5;
    private final int FSA_AKB_RUNNING = 6;
    private final int FSA_SETUP = 7;
    private final int FSA_SETUPING = 8;

    private static int btn_f;

    private static boolean setup_Flag;

    /*
    *   In normal mode,
    *   fname   the File Name of the log file
    *   fdata   the basic information & scores when AKB hit
    *   fnmap   Ports/OS when AKB hit, Nmap results when not hit
    *   fcurl   Curl results
    *   fint    flags
    *   flog    record FSA States changes
    */
    private static String fname;
    private static String fdata;
    private static String fnmap;
    private static String fcurl;
    private static StringBuffer flog;
    private static StringBuffer errlog;
    private static int fint;
    private String position;
    boolean isnewloc = false;
    int state = 0;

    /*
    *   state mode for Nmap scanning
    *   0   Normal FSA
    *   1   Nmap always scan
    */
    private final int MODELSTATE_NORMAL = 0;
    private final int MODELSTATE_NMAP_ALWAYS_SCAN = 1;
    private final int MODELSTATE_NO_NMAP_SCAN = 2;
    int modeState;


    private String nprint( String s) {
        if( s == null) {
            return "NULL";
        } else {
            return s;
        }
    }
    private String intToIp( int i) {
        return (i & 0xFF ) + "." + ((i >> 8 ) & 0xFF) + "." + ((i >> 16 ) & 0xFF) + "." + ( i >> 24 & 0xFF) ;
    }
    public static String execShellStr( String cmd) {
        System.out.println(cmd);
        errlog.append("=== CMD : ");
        errlog.append(cmd.replace(" && ","\n=== CMD : "));
        long time = System.currentTimeMillis();
        errlog.append(" : ");
        errlog.append(time);
        errlog.append("\n");
        String[] cmdStrings = new String[] {"sh", "-c", cmd};
        String retString = "";
        try {
            Process process = Runtime.getRuntime().exec(cmdStrings);
            BufferedReader stdout = new BufferedReader(new InputStreamReader( process.getInputStream()), 7777);
            BufferedReader stderr = new BufferedReader(new InputStreamReader( process.getErrorStream()), 7777);
            String line;
            while( ( ( line = stdout.readLine()) != null) || ( ( line = stderr.readLine())!= null)) {
                retString += line + "\n";
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return retString;
    }

    /*
    *   Search the AP Information Knowledge Base
    *   return -1   no match
    *   return >0   return value is the score, and the information will be stored in fdata.
    */
    private int searchAKB() {
        try {
            if (model.equals("Null")) {
                return -1;
            }
            BufferedReader reader = new BufferedReader(new InputStreamReader(getResources().getAssets().open("ap.csv")));
            String testmodel[] = model.split("\\s+");
            String modeltype;
            if( testmodel.length > 1) {
                modeltype = testmodel[testmodel.length-1].toUpperCase();
            } else {
                modeltype = model.toUpperCase();
            }
            try {
                String line;
                while ((line = reader.readLine()) != null) {
                    String qs[] = line.split(",");
                    if (qs.length < 2) continue;
                    //System.out.println("AP:" + qs[0] + "," + qs[1]);
                    if (modeltype.equals(qs[0].toUpperCase())) {
                        StringBuffer details = new StringBuffer("\nPort#\tService\tVersion\tScore\n");
                        for( int i = 2; i < qs.length; i ++) {
                            details.append(qs[i]);
                            details.append("\n");
                        }
                        fnmap = details.toString();
                        return Integer.parseInt(qs[1]);
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                reader.close();
            }
            return -1;
        } catch (Exception e) {
            e.printStackTrace();
            return -1;
        }
    }
    //by Haibin Lee: the following code gets the location.
    LocationListener locationListener = new LocationListener() {
        public void onLocationChanged(Location location) {
            isnewloc = true;

        }
        public void onStatusChanged(String provider, int status, Bundle extras) {}
        public void onProviderEnabled(String provider) {}
        public void onProviderDisabled(String provider) {}
    };
    public Location getLocation() {
        LocationManager locationManager = (LocationManager) this.getSystemService(Context.LOCATION_SERVICE);
        boolean isGPSEnabled = locationManager.isProviderEnabled(LocationManager.GPS_PROVIDER);
        boolean isNetworkEnabled = locationManager.isProviderEnabled(LocationManager.NETWORK_PROVIDER);
        PackageManager pm = getPackageManager();
        boolean permission = (PackageManager.PERMISSION_GRANTED == pm.checkPermission( "android.permission.ACCESS_FINE_LOCATION", ""));
        //System.out.println( "2:" + permission);
        if( isGPSEnabled || isNetworkEnabled) {
            Location loc = locationManager.getLastKnownLocation(LocationManager.PASSIVE_PROVIDER);
            if( loc == null) {
                position = "no valid location information";
                return null;
            } else {
                //System.out.println( "1::" + loc);
                //System.out.println( "2::" + loc.getLatitude());
                position = "Lat:" + loc.getLatitude() + ";  Long:" + loc.getLongitude();
                return loc;
            }
        } else {
            position = "Location by both Network and GPS Not Active ";
        }
        return null;
    }

    public void getWiFiInfo() {
        WifiManager wifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        if( !wifiManager.isWifiEnabled()) {
            wifiManager.setWifiEnabled(true);
        }
        WifiInfo wifiInfo = wifiManager.getConnectionInfo();

        DhcpInfo dhcp = wifiManager.getDhcpInfo();
        gatewayIP = Formatter.formatIpAddress(dhcp.gateway);
        ip = intToIp(wifiInfo.getIpAddress());
        ssid = wifiInfo.getSSID().replace("\"","");
        bssid = wifiInfo.getBSSID();
        address = wifiInfo.getMacAddress();
        //System.out.println("IP: " + ip);
        myTextView = (TextView) findViewById(R.id.main_display);

        getLocation();
        String str = getResources().getString(R.string.main_dispaly);
        String strr = String.format(str, ssid, bssid, ip, gatewayIP, position, "");
        myTextView.setText(strr);
        nmapRes = (TextView) findViewById(R.id.nmap_res);
        //myButton = (Button) findViewById(R.id.btn_nmap);
        flog.append("Start");

        fname = "LOG_" + bssid.replace( ":", "").toUpperCase() + "_" + modeState + ".txt";

        String[] qs = gatewayIP.split("\\.");
        //System.out.println(qs.length);
        if( qs.length == 4) {
            //System.out.println( qs[0] + " " + qs[1] + " " + qs[2] + " " + qs[3]);
            int ip1 = Integer.parseInt(qs[0]);
            int ip2 = Integer.parseInt(qs[1]);
            if ((ip1 == 10) || ((ip1 == 192) && (ip2 == 168)) || ((ip1 == 172) && (ip2 >= 16) && (ip2 < 32))) {
                nmapRes.setText(R.string.nmap_IPConfirmed);
                nmapRes.setTextColor(getResources().getColor(R.color.yellow));
                //myButton.setText(R.string.btn_Run);
                //myButton.setTextColor(getResources().getColor(R.color.red_light));
                btn_f = FSA_MODEL_RUNING;
                new Thread(runnableCurl).start();
                //new Thread(runnableWeb).start();
                //tcurl.start();
            } else {
                nmapRes.setText(R.string.warning_notLAN);
            }
        } else {
            nmapRes.setText(R.string.warning_invalidIP);
        }
    }
    private void gotoDisplay() {
        Intent intent = new Intent(MainActivity_backup.this, Display.class);
        /*Bundle bundle = new Bundle();
        bundle.putString("name", fname);
        bundle.putString("data", fdata);
        bundle.putString("nmap", fnmap);
        bundle.putString("curl", fcurl);
        bundle.putString("flog", flog.toString());
        bundle.putString("error", errlog.toString());
        bundle.putString("ip", gatewayIP);
        bundle.putString("ssid", ssid);
        bundle.putInt("fint", fint);
        bundle.putInt("state", modeState);
        intent.putExtras(bundle);//*/
        startActivity(intent);
    }
    @SuppressWarnings("deprecation")
    public void startNmap(View view) {
        //System.out.println("FSA: "+btn_f);
        if (btn_f == FSA_SETUP) {
            modeState = ReadConfig();
            btn_f = FSA_SETUPING;
            runnableSetupNmap.setView(view);
            new Thread(runnableSetupNmap).start();
        } else if( btn_f == FSA_START) {
            modeState = ReadConfig();
            getWiFiInfo();
        } else if (btn_f == FSA_NMAP_DONE) {
            gotoDisplay();
        }
    }
    /*
    *   FSA Changing, no need to hit the button.
     */
    private void S_FSA() {
        if( setup_Flag && ( btn_f == FSA_START)) {
            getWiFiInfo();
        }
        if( btn_f == FSA_MODEL) {
            String str = "SSID: %1$S\nBSSID: %2$S\nYour IP: %3$S\nGateway: %4$S\nLocation: %5$S\nModel: %6$S\n";
            String strr = String.format( str, ssid, bssid, ip, gatewayIP, position, model);
            fdata = strr + "\n" + "Device MAC: " + address + "\n";
            btn_f = FSA_AKB_RUNNING;
            new Thread(runnableAKB).start();
            //takb.start();
        } else {
            if( btn_f == FSA_NMAP_DONE) {
                gotoDisplay();
            } else {
                if( btn_f == FSA_NMAP_READY) {
                    btn_f = FSA_NMAP_RUNNING;
                    nmapRes = (TextView) findViewById(R.id.nmap_res);
                    nmapRes.setText(R.string.nmap_Run);
                    new Thread(runnableSend).start();
                    new Thread(runnableScan).start();
                }
            }
        }
    }
    /*
    *   Get the redirect Url of the default page.
    *   Huawei  /html/index.html
    *   Newifi  /cgi-bin/luci
    *   location.href = "../logon/logon.htm";
    */
    private String getUrl( String s) {
        try {
            if( s == null) {
                return null;
            }
            String[] qs = s.split("\n");
            for( String q : qs) {
                String qsu = q.toLowerCase();
                if( qsu.contains("/html/index.html")) {
                    return "/html/index.html";
                }
                if( qsu.contains("/cgi-bin/luci")) {
                    return "/cgi-bin/luci";
                }
                if( qsu.contains("/logon/logon.htm")) {
                    return "/logon/logon.htm";
                }
                if( qsu.contains("/login.htm")) {
                    return "/login.htm";
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }
    /*
    *   Get the Model from the <title> </title>
     */
    private String getHttpTitle( String s) {
        try {
            if( s == null) {
                return "NULL";
            }
            String[] qs = s.split("\n");
            for( String q : qs) {
                String qsu = q.toUpperCase();
                int index1 = qsu.lastIndexOf("<TITLE>") + 7;
                int index2 = qsu.indexOf("</TITLE>");
                if( ( index1 >= 0) && (index2 > index1)) {
                    errlog.append("=== _getHttpTitle: ");
                    errlog.append("[");
                    errlog.append(index1);
                    errlog.append(":");
                    errlog.append(index2);
                    errlog.append("]: ");
                    errlog.append(qsu);
                    errlog.append("\n");

                    return q.substring( index1, index2).trim();
                }
            }
            return "NULL";
        } catch (Exception e) {
            return "NULL";
        }
    }
    public static String getContentFromIn(HttpURLConnection urlConn, String charset) {
        BufferedReader br = null;
        StringBuilder content = new StringBuilder(200);
        InputStream in = null;
        try {
            if(null == urlConn){
                return "";
            }
            if(!urlConn.getContentEncoding().isEmpty()) {
                String encode = urlConn.getContentEncoding().toLowerCase();
                if( ( !encode.isEmpty()) && ( encode.contains("gzip"))) {
                    in = new GZIPInputStream(urlConn.getInputStream());
                }
            }

            if (null == in) {
                in = urlConn.getInputStream();
            }
            if (null != in) {
                br = new BufferedReader(new InputStreamReader(in, charset));
                String line = "";
                while ((line = br.readLine()) != null) {
                    content.append(line);
                }
            }

        } catch ( IOException e) {
            e.printStackTrace();
        } finally {
            if (null != in) {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                in = null;
            }
            if (null != br) {
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                in = null;
            }
        }
        return content.toString();
    }
    class RunnableSetupNmap implements Runnable {
        View view;

        public void setView(View newView) {
            view = newView;
        }

        public void run() {
            if (btn_f == FSA_SETUPING) {
                Test.extractFiles(view);
                handler.sendEmptyMessageDelayed(SETUP_FINISHED, 0);
            }
        }
    }

    RunnableSetupNmap runnableSetupNmap = new RunnableSetupNmap();

    /*
    *   Send data to server after AKB Searching
    *   In case the nmap cancel before done
    */
    Runnable runnableSend = new Runnable(){
        @Override
        public void run() {
            try {
                String content = flog + "\n\n" + fdata + "\n\n=== CURL ===\n" + fcurl + "\n\n=== ERRLOG ===\n" + errlog + "\n";
                String urlParameters = "filename=" + URLEncoder.encode(fname, "UTF-8") + "&content=" + URLEncoder.encode(content,"UTF-8");
                URL url = new URL("http://safe-ap.peidan.me/log/log.php");
                HttpURLConnection connection = (HttpURLConnection)url.openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                connection.setRequestProperty("Content-Length", "" + Integer.toString(urlParameters.getBytes().length));
                connection.setRequestProperty("charset", "utf-8");

                connection.setUseCaches(false);
                connection.setDoInput(true);
                connection.setDoOutput(true);

                DataOutputStream wr = new DataOutputStream(connection.getOutputStream());
                wr.writeBytes(urlParameters); //Writes out the string to the underlying output stream as a sequence of bytes
                wr.flush(); // Flushes the data output stream.
                wr.close();

                int responseCode = connection.getResponseCode();
                System.out.println("Response Code: " + responseCode);
                InputStream is = connection.getInputStream();
                BufferedReader rd = new BufferedReader(new InputStreamReader(is));
                String line;
                while((line = rd.readLine()) != null) {
                    System.out.println(line);
                }
                rd.close();

                if( responseCode != 200) {
                    handler.sendEmptyMessageDelayed(SEND_FAILED, 0);
                } else {
                    handler.sendEmptyMessageDelayed(SEND_DONE, 0);
                }
                /*String cmd = "cd /data/data/com.netman.yukawa.safeap/ && ./curl -d \"filename=" + fname + "&content=" + content + "\" \"http://safe-ap.peidan.me/log/log.php\"";
                String cmd = "curl -d @/sdcard/SafeAP/" + fname + " \"http://safe-ap.peidan.me/log/log.php\"";
                String res = execShellStr(cmd);
                System.out.println(res);
                if (res.contains("Failed") || res.contains("failed") || res.contains("curl: (")) {
                    handler.sendEmptyMessageDelayed(UPDATE_UI_FAILED, 0);
                } else {
                    handler.sendEmptyMessageDelayed(UPDATE_UI_DONE, 0);
                }//*/
            } catch (Exception e) {
                e.printStackTrace();
                handler.sendEmptyMessageDelayed(SEND_FAILED, 0);
            }
        }
    };

    // Thread to search the AKB
    Runnable runnableAKB = new Runnable(){
        @Override
        public void run() {
            System.out.println("Search the AKB");
            flog.append("\nAKB__START,");
            long time = System.currentTimeMillis();
            flog.append(time);
            if( btn_f == FSA_AKB_RUNNING) {
                int rs = searchAKB();
                if( rs == -1) {
                    fint = -1;
                    handler.sendEmptyMessageDelayed( AKB_UI_FAILED, 0);
                } else {
                    fint = rs;
                    handler.sendEmptyMessageDelayed( AKB_UI_DONE, 0);
                }
            } else {
                handler.sendEmptyMessageDelayed( THREAD_ERROR_AKB, 0);
            }
        }
    };

    public void getPicture() {
        try {
            //Thread.sleep(2000);
            float scale = webView.getScale();
            int height = (int) (webView.getContentHeight() * scale + 0.5);
            System.out.println("Bitmap: "+webView.getWidth()+" "+height+" "+scale+" "+webView.getContentHeight());
            Bitmap bitmap = Bitmap.createBitmap(webView.getWidth(), height, Bitmap.Config.ARGB_8888);
            Canvas canvas = new Canvas(bitmap);
            webView.draw(canvas);

            String path = Environment.getExternalStorageDirectory().toString();
            System.out.println("Path: " + path);
            OutputStream fOut = null;
            File file = new File(path + "/SafeAP/", fname.replace(".txt", ".png"));
            fOut = new FileOutputStream(file);

            bitmap.compress(Bitmap.CompressFormat.PNG, 50, fOut);
            fOut.flush();
            fOut.close();
            bitmap.recycle();
            //handler.sendEmptyMessageDelayed( PIC_DONE, 0);
        } catch (Exception e) {
            Log.e("error",Log.getStackTraceString(e));
        }
    }


    // Thread to capture the Webpage
    Runnable runnableWeb = new Runnable(){
        @Override
        public void run() {
            try {
                webView = (WebView) findViewById(R.id.webview_main);

                webView.setDrawingCacheEnabled(true);
                if( Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
                    WebView.enableSlowWholeDocumentDraw();
                }
                webView.post(new Runnable() {
                    public void run() {
                        webView.loadUrl("http://" + gatewayIP);
                        //webView.loadUrl("http://stackoverflow.com/questions/4302912/");
                        webView.getSettings().setUseWideViewPort(true);
                        webView.getSettings().setLoadWithOverviewMode(true);
                        webView.setWebViewClient(new WebViewClient() {
                            @Override
                            public void onPageFinished(WebView view, String url) {
                                try {
                                    /*Thread.sleep(2000);
                                    float scale = webView.getScale();
                                    int height = (int) (webView.getContentHeight() * scale + 0.5);
                                    System.out.println("Bitmap: "+webView.getWidth()+" "+height+" "+scale+" "+webView.getContentHeight());
                                    Bitmap bitmap = Bitmap.createBitmap(webView.getWidth(), height, Bitmap.Config.ARGB_8888);
                                    Canvas canvas = new Canvas(bitmap);
                                    webView.draw(canvas);

                                    String path = Environment.getExternalStorageDirectory().toString();
                                    System.out.println("Path: " + path);
                                    OutputStream fOut = null;
                                    File file = new File(path + "/SafeAP/", fname.replace(".txt", ".png"));
                                    fOut = new FileOutputStream(file);

                                    bitmap.compress(Bitmap.CompressFormat.PNG, 50, fOut);
                                    fOut.flush();
                                    fOut.close();
                                    bitmap.recycle();//*/
                                    //handler.sendEmptyMessageDelayed( PIC_DONE, 0);
                                } catch (Exception e) {
                                    Log.e("error",Log.getStackTraceString(e));
                                }
                            }//*/
                        });
                        //handler.sendEmptyMessageDelayed( PIC_DONE, 0);
                    }
                });
                //Thread.sleep(5000);
            } catch ( Exception e) {
                Log.e("error",Log.getStackTraceString(e));
            }
        }
    };


    // Thread to get the Model of the AP
    Runnable runnableCurl = new Runnable(){
        @Override
        public void run() {
            try {
                int check_salt = salt;
                System.out.println("Model Probing");
                flog.append("\nPROB_START,");
                long time = System.currentTimeMillis();
                flog.append(time);
                if (btn_f == FSA_MODEL_RUNING) {
                    StringBuffer page = new StringBuffer();
                    URLConnection con = new URL("http://"+gatewayIP).openConnection();
                    con.setRequestProperty("User-Agent", "Mozilla/5.0");
                    //URLConnection con = new URL("https://appmind.peidan.me/agent_listener/invoke_raw_method?method=metric_data&marshal_format=json&protocol_version=14").openConnection();
                    con.connect();
                    InputStream is = con.getInputStream();
                    con.getURL();
                    System.out.println(con.getURL());
                    BufferedReader in = new BufferedReader(new InputStreamReader(is));
                    String inputLine;
                    while ((inputLine = in.readLine()) != null) {
                        page.append(inputLine);
                        page.append("\n");
                    }
                    in.close();
                    is.close();

                    //String cmdRes = execShellStr("cd /data/data/com.netman.yukawa.safeap/ && ./curl -k -L -e \'; auto\' " + gatewayIP);
                    String cmdRes = page.toString();
                    //try { Thread.sleep(20000);} catch (Exception e){};
                    model = getHttpTitle(cmdRes);
                    fcurl = "URL: " + con.getURL() + "\n" + cmdRes;
                    errlog.append("=== _runnableCurl[1] : ");
                    errlog.append(model);
                    time = System.currentTimeMillis();
                    errlog.append(" : ");
                    errlog.append(time);
                    errlog.append("\n");
                    if ((model == null) || (model.equals("NULL"))) {
                        String nurl = getUrl(cmdRes);
                        if (nurl != null) {
                            //cmdRes = execShellStr("cd /data/data/com.netman.yukawa.safeap/ && ./curl -k -L -e \'; auto\' " + gatewayIP + nurl);
                            page = new StringBuffer();
                            con = new URL("http://"+gatewayIP+nurl).openConnection();
                            con.connect();
                            is = con.getInputStream();
                            con.getURL();
                            in = new BufferedReader(new InputStreamReader(is));
                            while ((inputLine = in.readLine()) != null) {
                                page.append(inputLine);
                                page.append("\n");
                            }
                            in.close();
                            is.close();
                            model = getHttpTitle(cmdRes);
                            fcurl += "\n=== CURL " + nurl + "===\n" + cmdRes;
                            errlog.append("=== _runnableCurl[2] : ");
                            errlog.append(nurl);
                            errlog.append(" : ");
                            errlog.append(model);
                            time = System.currentTimeMillis();
                            errlog.append(" : ");
                            errlog.append(time);
                            errlog.append("\n");
                        }
                    }
                    System.out.println(nprint(model));
                    if (check_salt == salt) {
                        handler.sendEmptyMessageDelayed(CURL_UI_DONE, 0);
                    } else {
                        handler.sendEmptyMessageDelayed(EXPIRED, 0);
                    }
                } else {
                    handler.sendEmptyMessageDelayed(THREAD_ERROR_CURL, 0);
                }
            } catch (Exception e) {
                Log.e("error",Log.getStackTraceString(e));
                System.out.println("CURL ERROR");
                model = "Timeout";
                handler.sendEmptyMessageDelayed(CURL_UI_DONE, 0);
            }
        }
    };
    // In this thread, the btn_f should be 1. The Wifi informatino should be already got and displayed.
    // The model maybe fetched, and should be checked then.
    Runnable runnableScan = new Runnable(){
        @Override
        public void run() {
            int check_salt = salt;
            btn_f = FSA_NMAP_RUNNING;
            System.out.println("Scan Running");
            flog.append("\nSCAN_START,");
            long time = System.currentTimeMillis();
            flog.append(time);

            //fnmap =  execShellStr("cd /data/data/com.netman.yukawa.safeap/ && ./nmap -T4 -sV -Pn " + gatewayIP);

            if( check_salt == salt) {
                handler.sendEmptyMessageDelayed( SCAN_UI_DONE, 0);
            } else {
                handler.sendEmptyMessageDelayed( EXPIRED, 0);
            }
        }
    };
    /*
    Handler to child thread
    UPDATE_UI_DONE: curl done
    UPDATE_UI_FAILED: curl failed
    NMAP_UI_DONE: after the nmap script done
    */
    @SuppressWarnings("HandlerLeak")
    private Handler handler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            super.handleMessage(msg);
            long time;
            nmapRes = (TextView) findViewById(R.id.nmap_res);
            switch (msg.what) {
                case SETUP_FINISHED:
                    nmapRes.setText(R.string.setup_Done);
                    btn_f = FSA_START;
                    setup_Flag = true;
                    S_FSA();
                    break;
                case EXPIRED:
                    System.out.println("Thread Expired!");
                    break;
                case THREAD_ERROR_AKB:
                    nmapRes.setText(R.string.error);
                    errlog.append("\n### THREAD_ERROR_AKB: ");
                    time = System.currentTimeMillis();
                    errlog.append(time);
                    errlog.append("\n");
                    btn_f = FSA_START;
                    break;
                case THREAD_ERROR_CURL:
                    nmapRes.setText(R.string.error);
                    errlog.append("\n### THREAD_ERROR_CURL: ");
                    time = System.currentTimeMillis();
                    errlog.append(time);
                    errlog.append("\n");
                    btn_f = FSA_START;
                    break;
                case SCAN_UI_DONE:
                    nmapRes.setText(R.string.nmap_Done);
                    btn_f = FSA_NMAP_DONE;
                    flog.append("\nSCAN__DONE,");
                    time = System.currentTimeMillis();
                    flog.append(time);
                    S_FSA();
                    break;
                case CURL_UI_DONE:
                    if( model == null) {
                        model = "Null";
                    }
                    myTextView = (TextView) findViewById(R.id.main_display);
                    String str = getResources().getString(R.string.main_dispaly);
                    String strr = String.format( str, ssid, bssid, ip, gatewayIP, position, model);
                    myTextView.setText(strr);
                    nmapRes = (TextView) findViewById(R.id.nmap_res);
                    nmapRes.setText(R.string.model_Done);
                    flog.append("\nPROB__DONE,");
                    time = System.currentTimeMillis();
                    flog.append(time);
                    btn_f = FSA_MODEL;
                    S_FSA();
                    break;
                case AKB_UI_DONE:
                    nmapRes.setText(R.string.akb_Done);
                    if( modeState == MODELSTATE_NMAP_ALWAYS_SCAN) {
                        btn_f = FSA_NMAP_READY;
                    } else {
                        btn_f = FSA_NMAP_DONE;
                    }
                    flog.append("\nAKB___DONE,");
                    time = System.currentTimeMillis();
                    flog.append(time);
                    S_FSA();
                    break;
                case AKB_UI_FAILED:
                    nmapRes.setText(R.string.akb_Failed);
                    btn_f = FSA_NMAP_READY;
                    flog.append("\nAKB___DONE,");
                    time = System.currentTimeMillis();
                    flog.append(time);
                    S_FSA();
                    break;
                case SEND_FAILED:
                    break;
                case SEND_DONE:
                    break;
                case PIC_DONE:
                    webView.setVisibility(View.GONE);
                    break;
                default:
                    Bundle data = msg.getData();
                    String val = data.getString("value");
                    Log.i( "Result: ", val);
                    break;
            }
        }
    };

    @SuppressWarnings("deprecation")
    public void clear( View view) {
        modeState = ReadConfig();
        nmapRes = (TextView) findViewById(R.id.nmap_res);
        if(setup_Flag) {
            btn_f = FSA_START;
            switch (modeState) {
                case MODELSTATE_NORMAL:
                    nmapRes.setText(R.string.setup_Done);
                    break;
                case MODELSTATE_NMAP_ALWAYS_SCAN:
                    nmapRes.setText(R.string.mode_Nmap_Always_Scan);
                    break;
                case MODELSTATE_NO_NMAP_SCAN:
                    nmapRes.setText(R.string.mode_No_Nmap_Scan);
                    break;
                default:
                    nmapRes.setText(R.string.setup_Done);
                    break;
            }
        } else {
            btn_f = FSA_SETUP;
            nmapRes.setText(R.string.setup_Failed);
        }
        fint = 0;
        flog = new StringBuffer();
        errlog = new StringBuffer();
        fname = "";
        fdata = "";
        fnmap = "";
        fcurl = "";
        salt = (int)System.currentTimeMillis();
        //tcurl.interrupt();
        //takb.interrupt();
        //tnmap.interrupt();
        myTextView = (TextView) findViewById(R.id.main_display);

        myButton = (Button) findViewById(R.id.btn_nmap);

        String str = getResources().getString(R.string.main_dispaly);
        String strr = String.format( str, "", "", "", "", "", "");
        myTextView.setText(strr);
        /*State appState = ((State) getApplicationContext());
        state = appState.getState();
        String modeStateD = getResources().getString(R.string.nmap_Ready);
        String modeState = String.format(modeStateD, state);
        nmapRes.setText(modeState);
        //*/
        nmapRes.setTextColor(getResources().getColor(R.color.white));
        myButton.setText("");
    }

    public void goToTest( View view) {
        Intent intent = new Intent( MainActivity_backup.this, Test.class);
        startActivity(intent);
    }
    private int ReadConfig() {
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader( openFileInput("config.txt")));
            int res = Integer.parseInt(reader.readLine());
            reader.close();
            return res;
        } catch (Exception e) {
            e.printStackTrace();
            return 1;
        }
    }
    @Override
    protected void onCreate( Bundle savedInstanceState) {
        btn_f = FSA_SETUP;
        setup_Flag = false;
        fint = 0;
        flog = new StringBuffer();
        errlog = new StringBuffer();
        fname = "";
        fdata = "";
        fnmap = "";
        fcurl = "";
        salt = (int)System.currentTimeMillis();
        //tcurl = new Thread(runnableCurl);
        //tnmap = new Thread(runnableNmap);
        //takb = new Thread(runnableAKB);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        gotoDisplay();
        myTextView = (TextView) findViewById(R.id.main_display);
        nmapRes = (TextView) findViewById(R.id.nmap_res);
        myButton = (Button) findViewById(R.id.btn_nmap);

        String str = getResources().getString(R.string.main_dispaly);
        String strr = String.format( str, "", "", "", "", "", "");
        myTextView.setText(strr);

        // Check if nmap has already been installed
        String[] testResult = Test.execShellStr("cd /data/data/com.netman.yukawa.safeap && ls").split("\n");
        int found = 0;
        for( String s : testResult) {
            if( s.compareTo("nmap") == 0) {
                ++found;
            } else if( s.compareTo("curl") == 0) {
                ++found;
            } else if( s.compareTo("busybox") == 0) {
                ++found;
            }
        }
        if( found > 2) {
            modeState = ReadConfig();
            switch (modeState) {
                case MODELSTATE_NORMAL:
                    nmapRes.setText(R.string.setup_Done);
                    break;
                case MODELSTATE_NMAP_ALWAYS_SCAN:
                    nmapRes.setText(R.string.mode_Nmap_Always_Scan);
                    break;
                case MODELSTATE_NO_NMAP_SCAN:
                    nmapRes.setText(R.string.mode_No_Nmap_Scan);
                    break;
                default:
                    nmapRes.setText(R.string.setup_Done);
                    break;
            }
            btn_f = FSA_START;
            setup_Flag = true;
        } else {
            nmapRes.setText(R.string.setup_Failed);
        }

        /*
        *   Mode choose
        *   If config file exists, read from it.
        *   Else, create one
        */

        /*State appState = ((State) getApplicationContext());
        state = appState.getState();
        /*String modeStateD = getResources().getString(R.string.nmap_Ready);
        String modeState = String.format(modeStateD, state);
        nmapRes.setText(modeState);
        //*/
        //nmapRes.setText(R.string.nmap_Ready);
        myButton.setText("");

        //by Haibin Lee:the following code checks whether the location servici is actived, and suggest the user to enable them if not.
        LocationManager lm = (LocationManager) getSystemService(LOCATION_SERVICE);
        if(!lm.isProviderEnabled(LocationManager.GPS_PROVIDER) &&
                !lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) {
            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setTitle("Location by both Network and GPS Not Active");
            builder.setMessage("Please enable Location by Network and GPS");
            builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialogInterface, int i) {
                    Intent intent = new Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS);
                    startActivity(intent);
                }
            });
            Dialog alertDialog = builder.create();
            alertDialog.setCanceledOnTouchOutside(false);
            alertDialog.show();
        }
        if(lm.isProviderEnabled(LocationManager.GPS_PROVIDER)&&
                !lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) {
            AlertDialog.Builder builder1 = new AlertDialog.Builder(this);
            builder1.setTitle("Location by Network Not Active");
            builder1.setMessage("Please enable Location by Network");
            builder1.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialogInterface, int i) {
                    Intent intent = new Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS);
                    startActivity(intent);
                }
            });
            Dialog alertDialog1 = builder1.create();
            alertDialog1.setCanceledOnTouchOutside(false);
            alertDialog1.show();

        }
        if(!lm.isProviderEnabled(LocationManager.GPS_PROVIDER)&&
                lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) {
            AlertDialog.Builder builder2 = new AlertDialog.Builder(this);
            builder2.setTitle("Location by GPS Not Active");
            builder2.setMessage("Please enable Location by GPS");
            builder2.setPositiveButton("OK", new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialogInterface, int i) {
                    Intent intent = new Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS);
                    startActivity(intent);
                }
            });
            Dialog alertDialog2 = builder2.create();
            alertDialog2.setCanceledOnTouchOutside(false);
            alertDialog2.show();
        }
        LocationManager lm0 = (LocationManager) this.getSystemService(Context.LOCATION_SERVICE);
        /*PackageManager pm = getPackageManager();
        int permission = pm.checkPermission( "android.permission.ACCESS_FINE_LOCATION", "");
        System.out.println(permission);
        permission = (PackageManager.PERMISSION_GRANTED == pm.checkPermission( "android.permission.ACCESS_COARSE_LOCATION", ""));
        System.out.println(PackageManager.PERMISSION_GRANTED);
        int permissionCheck = ContextCompat.checkSelfPermission( this, Manifest.permission.ACCESS_FINE_LOCATION);
        System.out.println(permissionCheck);//*/
        if( ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, new String[]{Manifest.permission.ACCESS_FINE_LOCATION}, 0);
        }

        lm0.requestLocationUpdates(LocationManager.NETWORK_PROVIDER, 0, 0, locationListener);
        lm0.requestLocationUpdates(LocationManager.GPS_PROVIDER, 0, 0, locationListener);
        if (isnewloc) {
            lm0.removeUpdates(locationListener);
        }
    }
}