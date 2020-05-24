package com.netman.yukawa.safeap;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.graphics.Color;
import android.net.DhcpInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.text.Html;
import android.text.format.Formatter;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.github.lzyzsd.circleprogress.ArcProgress;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {
    private final int THREAD_ERROR = -3;
    private final int SETUP_FINISHED = -2;
    private final int EXPIRED = -1;
    private final int UPDATE_UI_FAILED = 0;
    private final int UPDATE_UI_DONE = 1;
    private final int WRITE_FILE_DONE = 2;
    private final int NMAP_UI_DONE = 3;
    private final int NET_UI_DONE = 4;
    private final int NET_UI_FAIL = 5;
    private final int DNS_UI_DONE = 6;
    private final int DNS_UI_FAIL = 7;
    private final int ARP_UI_DONE = 8;
    private final int ARP_UI_FAIL = 9;
    private final int CURL_UI_DONE = 10;
    private final int AKB_UI_DONE = 11;
    private final int AKB_UI_FAILED = 12;

    private int config_State = 0;


    //private static int send_Flag = 0;
    private static int retrans = 5; //Retransmission times
    private static String fout;
    private static String fname;
    //private static String fdata;
    private static String fnmap;
    private static String fcurl;
    private static StringBuffer flog;
    //private static String errorlog;

    private String ip;
    private String ssid;
    private String bssid;
    private String gatewayIP;
    private String model;
    private String address;
    private String position;

    //private static int fint;
    //private static String fsend;
    //private static int state;

    private int salt;

    private static int ver1;
    private static int ver2;
    private static int ver3;
    private static int ver4;

    private static int sum_Score;//score for Nmap scanning
    private static int check_Score;//score for DNS ARP & etc check

    /*
    *   When search the VKB, means the vercheck is valid
    *   Then the ver1-4 has values
    */
    private int searchVKB( String s) {
        //System.out.println("Search the VKB: " + s);
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader( getResources().getAssets().open("vkb.csv")));
            try {
                String line;
                //int cnt = 1;
                int sum = 0;
                while( ( line = reader.readLine()) != null) {
                    String qs[] = line.split(",");
                    if( qs.length != 3) continue;
                    //System.out.println("VKB:" + qs[0] + "," + qs[1] + "," + qs[2]);
                    //todo Search the range of the version
                    if(s.equals(qs[0].toUpperCase())) {
                        if(smallerVer(qs[1])) {
                            sum = Integer.parseInt(qs[2]);
                        } else {
                            return sum;
                        }
                    } else {
                        if( sum != 0) {
                            return sum;
                        }
                    }
                }
            } catch ( Exception e) {
                e.printStackTrace();
            } finally {
                reader.close();
            }
            return -1;
        } catch ( Exception e) {
            e.printStackTrace();
            return -1;
        }
    }
    /*
    *   Check if the version is in the keyword list and if we get a version number or not
    *   If in the keywork list and no version, return score from the keyword list
    *   If have version, search the VKB with the keyword
    *   Return the Standard Output
    *   [port#] [service] [version] : [scores]
    */
    private String searchKeywords( String s) {
        //System.out.println("Search the Keywords: " + s);
        try {
            String qs[] = s.split("\\s+");

            /*
            *   e.g.    s   80/tcp open http nginx 1.6.2
            *   qs[0]   [port]/tcp
            *   qs[1]   open or close or filtered
            *   qs[2]   [service]
            *   qs[3+]   [software] & [version]
            */
            int port = Integer.parseInt(qs[0].split("/")[0]);
            int n = qs.length;
            if( n > 3) {
                StringBuilder version = new StringBuilder();
                version.append(qs[3]);
                for (int i = 4; i < n; i++) {
                    version.append(" ");
                    version.append(qs[i]);
                }
                BufferedReader reader = new BufferedReader(new InputStreamReader(getResources().getAssets().open("keyword.csv")));
                try {
                /*
                *   First, try to match the keyword. Two matches model: contains / equal
                *   Example.
                *   contains:   nginx 1.7.5, contains keyword nginx -> go to VKB
                *               when contains, the last segment of the String should be the version
                *   equals:     nginx in keyword.csv, return scores
                 */
                    String line;
                    String ver = version.toString().toUpperCase();
                    while ((line = reader.readLine()) != null) {
                        String qss[] = line.toUpperCase().split(",");
                        if (qss.length != 2) continue;
                        //System.out.println("Keyword:" + qss[0] + "," + qss[1]);
                        if (ver.contains(qss[0])) {
                            boolean ver_flag = checkVersion(qs[n-1].toUpperCase());
                            if(ver_flag) {
                                int score = searchVKB(qss[0]);
                                sum_Score += score;
                                return (port + "\t" + qs[2] + "\t" + version.toString() + " : " + score);
                            } else {
                                sum_Score += Integer.parseInt(qss[1]);
                                return (port + "\t" + qs[2] + "\t" + version.toString() + " : " + qss[1]);
                            }
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    reader.close();
                }
                return (port + "\t" + qs[2] + "\t" + version);
            } else {
                return (port + "\t" + qs[2]);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return s;
        }
    }
    /*
    *   Metrics for the final score
    *   Input: weight w, scores s
    *   Sum = sigma( w * s)
    */
    private int normalization(int n) {
        int a[] = {0,13,30,50,75,85,100};
        int x[] = {0,111,151,300,450,850,1400};
        for( int i = 1; i < 6; i ++) {
            if( n < x[i]) {
                return ( 10 * a[i-1] + 10 * ( a[i] - a[i-1]) * ( n - x[i-1]) / ( x[i] - x[i-1]));
            }
        }
        return 1000;
    }
    @SuppressWarnings("deprecation")
    private void getFinalScore() {
        ArcProgress arc = (ArcProgress) findViewById(R.id.arc_progress);
        System.out.println(check_Score);
        //TextView myTextView = (TextView) findViewById(R.id.display_display);
        TextView myTextView1 = (TextView) findViewById(R.id.display_display_1);

        int score = normalization(check_Score/2) / 10;
        //score = 92;
        //String str = getResources().getString(R.string.display_display);
        //String strr = String.format(str, score) + "%";
        String str1 = getResources().getString(R.string.display_display_1);
        String strr1;
        if( score < 40) {
            //myTextView.setTextColor(getResources().getColor(R.color.green));
            arc.setFinishedStrokeColor(Color.rgb(0x11,0xFF,0x55));
            //arc.setTextColor(Color.GREEN);

            String sss = getResources().getString(R.string.safe);
            strr1 = String.format( str1, "<font color='#11FF55'>" + sss + "</font>");
        } else {
            if( score < 80) {
                //myTextView.setTextColor(getResources().getColor(R.color.yellow));
                arc.setFinishedStrokeColor(Color.rgb(0xFF,0xCD,0x22));
                //arc.setTextColor(Color.YELLOW);
                String sss = getResources().getString(R.string.medium);
                strr1 = String.format( str1, "<font color='#FFCD22'>" + sss + "</font>");
            } else {
                //myTextView.setTextColor(getResources().getColor(R.color.red_dark));
                arc.setFinishedStrokeColor(Color.rgb(0xB5,0x22,0x21));
                //arc.setTextColor(Color.RED);
                String sss = getResources().getString(R.string.vulnerable);
                strr1 = String.format( str1, "<font color='#B52121'>" + sss + "</font>");
            }
        }
        arc.setProgress(score);

        //myTextView.setText(strr);
        myTextView1.setText(Html.fromHtml(strr1), TextView.BufferType.SPANNABLE);
    }
    /*
    *   Check if the String is a valid version
    *   The valid version is :   1.2.3(a|b|rc[0-9]+)
    */
    private boolean checkVersion( String s) {
        try {
            String qs[] = s.toUpperCase().split("\\.");
            int n = qs.length;
            switch (n) {
                case 0:
                    return false;
                case 1:
                    ver1 = Integer.parseInt(qs[0]);
                    ver2 = 0;
                    ver3 = 0;
                    ver4 = 0;
                    return true;
                case 2:
                    ver1 = Integer.parseInt(qs[0]);
                    ver2 = Integer.parseInt(qs[1]);
                    ver3 = 0;
                    ver4 = 0;
                    return true;
                case 3:
                    ver1 = Integer.parseInt(qs[0]);
                    ver2 = Integer.parseInt(qs[1]);
                    String qss[] = qs[2].split("[^\\d]");
                    if (qss.length > 1) {
                        ver3 = Integer.parseInt(qss[0]);
                        ver4 = Integer.parseInt(qss[1]);
                        if (qs[2].contains("A")) {
                            ver4 *= 10000;
                        } else {
                            if (qs[2].contains("B")) {
                                ver4 *= 100;
                            } else {
                                ver4 *= 1;
                            }
                        }
                        ver4 = 0 - ver4;
                    } else {
                        ver3 = Integer.parseInt(qs[2]);
                        ver4 = 0;
                    }
                    return true;
                default:
                    return false;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    private boolean smallerVer( String s) { //Check if the target version is <= the ver1-4
        try {
            int t1 = 0;
            int t2 = 0;
            int t3 = 0;
            int t4 = 0;
            String qs[] = s.toUpperCase().split("\\.");
            int n = qs.length;
            switch (n) {
                case 0:
                    break;
                case 1:
                    t1 = Integer.parseInt(qs[0]);
                    t2 = 0;
                    t3 = 0;
                    t4 = 0;
                    break;
                case 2:
                    t1 = Integer.parseInt(qs[0]);
                    t2 = Integer.parseInt(qs[1]);
                    t3 = 0;
                    t4 = 0;
                    break;
                case 3:
                    t1 = Integer.parseInt(qs[0]);
                    t2 = Integer.parseInt(qs[1]);
                    String qss[] = qs[2].split("[^\\d]");
                    if (qss.length > 1) {
                        t3 = Integer.parseInt(qss[0]);
                        t4 = Integer.parseInt(qss[1]);
                        if (qs[2].contains("A")) {
                            t4 *= 10000;
                        } else {
                            if (qs[2].contains("B")) {
                                t4 *= 100;
                            } else {
                                t4 *= 1;
                            }
                        }
                        t4 = 0 - t4;
                    } else {
                        t3 = Integer.parseInt(qs[2]);
                        t4 = 0;
                    }
                    break;
                default:
                    return false;
            }
            if( t1 < ver1) {
                return true;
            } else {
                if( t1 == ver1) {
                    if( t2 < ver2) {
                        return true;
                    }
                    if( ( t2 == ver2) && ( t3 < ver3)) {
                        return true;
                    }
                    if( ( t2 == ver2) && ( t3 == ver3) && ( t4 < ver4)) {
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    private void WriteLogFile( StringBuffer Log, String filename) {
        String eol = System.getProperty("line.separator");
        try {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter( openFileOutput( filename, 2)));
            writer.write(Log.append(eol).toString());
            writer.close();
        } catch ( Exception e) {
            e.printStackTrace();
        }
    }
    public static String execShellStr( String cmd) {
        Log.w("System.out", "CMD: " + cmd);
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
            Log.w ("System.oeut", "CMD ERROR: " + e);
        }
        Log.w ("System.out", "CMD RES: " + retString);
        return retString;
    }
    /*Send the result to our server
        send_Flag: FSA State
        0   state
        1   sending
        2   done

    public void sendData( View view) { //curl -d "filename=aaa&content=1034285" "http://166.111.71.73/log/log.php"
        try {
            if( send_Flag == 0) {
                send_Flag = 1;
                System.out.println( fname + ":" + fdata.length());
                System.out.println( "Curl:" + fcurl.length());
                new Thread(runnableSend).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }*/
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
                        StringBuilder details = new StringBuilder("\nPort#\tService\tVersion\tScore\n");
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
                    return q.substring( index1, index2).trim();
                }
            }
            return "NULL";
        } catch (Exception e) {
            return "NULL";
        }
    }
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
                    handler.sendEmptyMessageDelayed( AKB_UI_FAILED, 0);
                } else {
                    if( config_State == 0) {
                        handler.sendEmptyMessageDelayed( AKB_UI_FAILED, 0);
                    } else {
                        sum_Score = rs;
                        handler.sendEmptyMessageDelayed( AKB_UI_DONE, 0);
                    }
                }
            } else {
                handler.sendEmptyMessageDelayed( THREAD_ERROR, 0);
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
                if( btn_f == FSA_MODEL_RUNING) {
                    StringBuilder page = new StringBuilder();
                    URLConnection con = new URL("http://"+gatewayIP).openConnection();
                    con.setRequestProperty("User-Agent", "Mozilla/5.0");
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
                    String cmdRes = page.toString();
                    model = getHttpTitle(cmdRes);
                    fcurl = "URL: " + con.getURL() + "\n" + cmdRes;
                    if( check_salt == salt) {
                        handler.sendEmptyMessageDelayed( CURL_UI_DONE, 0);
                    } else {
                        handler.sendEmptyMessageDelayed( EXPIRED, 0);
                    }
                } else {
                    handler.sendEmptyMessageDelayed( THREAD_ERROR, 0);
                }
            } catch (Exception e) {
                Log.e("error",Log.getStackTraceString(e));
                System.out.println("CURL ERROR");
                model = "Timeout";
                handler.sendEmptyMessageDelayed(CURL_UI_DONE, 0);
            }
        }
    };
    Runnable runnableSend = new Runnable(){
        @Override
        public void run() {
            try {
                //String content = flog + "\n\n" + fsend + "\n\n=== CURL ===\n" + fcurl + "\n\n=== ERRLOG ===\n" + errorlog + "\n";
                String content = flog + "\n\n" + fout + "\n";
                String urlParameters = "filename=" + URLEncoder.encode(fname,"UTF-8") + "&content=" + URLEncoder.encode(content,"UTF-8");
                //String urlParameters = "filename=" + URLEncoder.encode("xxx","UTF-8") + "&content=" + URLEncoder.encode("123","UTF-8");
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
                    handler.sendEmptyMessageDelayed(UPDATE_UI_FAILED, 0);
                } else {
                    handler.sendEmptyMessageDelayed(UPDATE_UI_DONE, 0);
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
            }
        }
    };
    Runnable runnableWriteLog = new Runnable(){
        @Override
        public void run() {
            WriteLogFile(new StringBuffer("filename=" + fname + "&content=" + flog + "\n\n" + fout), fname);
            execShellStr("cat /data/data/com.netman.yukawa.safeap/files/" + fname + " > /sdcard/SafeAP/" + fname);
            execShellStr("rm /data/data/com.netman.yukawa.safeap/files/" + fname);
            handler.sendEmptyMessageDelayed(WRITE_FILE_DONE, 0);
        }
    };
    Runnable runnableNmap = new Runnable(){
        @Override
        public void run() {
            if( btn_f != FSA_NMAP_RUNNING) return;
            int check_salt = salt;
            System.out.println("Nmap Running");
            flog.append("\nNMAP_START,");
            long time = System.currentTimeMillis();
            flog.append(time);
            fnmap = execShellStr("cd /data/data/com.netman.yukawa.safeap/ && ./nmap -T4 -sV -Pn -p22,23,53,80,443,1900,8000,8080 " + gatewayIP);
            System.out.println("FNMAP: " + fnmap);
            if( check_salt == salt) {
                handler.sendEmptyMessageDelayed( NMAP_UI_DONE, 0);
            } else {
                handler.sendEmptyMessageDelayed( EXPIRED, 0);
            }
        }
    };
    Runnable runnableNet = new Runnable(){
        @Override
        public void run() {
            int check_salt = salt;
            System.out.println("NetCheck Running");
            flog.append("\nNET__START,");
            long time = System.currentTimeMillis();
            flog.append(time);
            //Process here
            try {
                URL url = new URL("http://www.baidu.com");
                HttpURLConnection connection = (HttpURLConnection)url.openConnection();
                connection.setRequestMethod("GET");
                connection.setRequestProperty("User-Agent", "Mozilla/5.0");
                connection.connect();
                connection.getInputStream();
                int responseCode = connection.getResponseCode();
                System.out.println("Baidu Response Code: " + responseCode + "," + connection.getURL());
                if( check_salt == salt) {
                    if( ( responseCode == 200) & ( connection.getURL().toString().contains("baidu.com"))){
                        handler.sendEmptyMessageDelayed( NET_UI_DONE, 0);
                    } else {
                        handler.sendEmptyMessageDelayed( NET_UI_FAIL, 0);
                    }
                } else {
                    handler.sendEmptyMessageDelayed( EXPIRED, 0);
                }
            } catch (Exception e) {
                Log.e("error", "Error: ", e);
                if( check_salt == salt) {
                    handler.sendEmptyMessageDelayed( NET_UI_FAIL, 0);
                } else {
                    handler.sendEmptyMessageDelayed( EXPIRED, 0);
                }
            }
        }
    };
    Runnable runnableDNS = new Runnable(){
        @Override
        public void run() {
            try {
                int check_salt = salt;
                System.out.println("DNSCheck Running");
                flog.append("\nDNS__START,");
                long time = System.currentTimeMillis();
                flog.append(time);
                //TODO: Process here
                /*InetAddress[] machines = InetAddress.getAllByName("www.taobao.com");
                for (InetAddress address : machines) {
                    System.out.println(address.getHostAddress());
                }//*/
                WifiManager wifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
                DhcpInfo dhcp = wifiManager.getDhcpInfo();
                if( dhcp != null) {
                    System.out.println("DNS1:" + intToIp(dhcp.dns1));
                    System.out.println("DNS2:" + intToIp(dhcp.dns2));
                }

                if( check_salt == salt) {
                    if( intToIp(dhcp.dns1).equals(gatewayIP)) {
                        handler.sendEmptyMessageDelayed( DNS_UI_DONE, 0);
                    } else {
                        handler.sendEmptyMessageDelayed( DNS_UI_FAIL, 0);
                    }
                } else {
                    handler.sendEmptyMessageDelayed( EXPIRED, 0);
                }
            } catch (Exception e) {
                Log.e("error","Error: ",e);
                handler.sendEmptyMessageDelayed(THREAD_ERROR, 0);
            }
        }
    };
    Runnable runnableARP = new Runnable(){
        @Override
        public void run() {
            int check_salt = salt;
            System.out.println("ARPCheck Running");
            flog.append("\nARP__START,");
            long time = System.currentTimeMillis();
            flog.append(time);
            boolean f_arp = true;
            try {
                BufferedReader br = new BufferedReader(new FileReader("/proc/net/arp"));
                String line;
                List<String> listIP = new ArrayList<>();
                while( ( line = br.readLine()) != null) {
                    Log.w("System.out",line);
                    // The ARP table has the form:
                    //   IP address        HW type    Flags     HW address           Mask   Device
                    //   192.168.178.21    0x1        0x2       00:1a:2b:3c:4d:5e    *      tiwlan0
                    String[] qs = line.split("\\s+");
                    if( qs.length >= 4) {
                        if( listIP.contains(qs[0])) {
                            f_arp = false;
                            break;
                        } else {
                            listIP.add(qs[0]);
                        }
                        if( listIP.contains(qs[3])) {
                            f_arp = false;
                            break;
                        } else {
                            listIP.add(qs[3]);
                        }
                    }
                }
                br.close();
            } catch( Exception e) { Log.e("error", "Error: ", e); handler.sendEmptyMessageDelayed( EXPIRED, 0);}
            if( check_salt == salt) {
                if( f_arp) {
                    handler.sendEmptyMessageDelayed( ARP_UI_DONE, 0);
                } else {
                    handler.sendEmptyMessageDelayed( ARP_UI_FAIL, 0);
                }
            } else {
                handler.sendEmptyMessageDelayed( EXPIRED, 0);
            }
        }
    };
    @SuppressWarnings("HandlerLeak")
    private Handler handler = new Handler() {
        @Override
        @SuppressWarnings("deprecation")
        public void handleMessage(Message msg) {
            super.handleMessage(msg);
            Button details = (Button)findViewById(R.id.btn_details);
            TextView tv;
            switch (msg.what) {
                case SETUP_FINISHED:
                    btn_f = FSA_START;
                    S_FSA();
                    break;
                case UPDATE_UI_FAILED:
                    //send_Flag = 0;
                    if( retrans > 0) {
                        retrans --;
                        new Thread(runnableSend).start();
                    }
                    break;
                case UPDATE_UI_DONE:
                    //send_Flag = 2;
                    break;
                case WRITE_FILE_DONE:
                    //send_Flag = 0;
                    new Thread(runnableSend).start();
                    break;
                case NMAP_UI_DONE:
                    btn_f = FSA_NMAP_DONE;
                    flog.append("\nNMAP__DONE,");
                    long time = System.currentTimeMillis();
                    flog.append(time);
                    dataProcess();
                    details.setText(R.string.btn_Details);
                    tv = (TextView)findViewById(R.id.display_display_0);
                    tv.setText(R.string.nmap_Done);
                    break;
                case NET_UI_DONE:
                    flog.append("\nNET___DONE,");
                    time = System.currentTimeMillis();
                    flog.append(time);
                    TextView tvNET = (TextView) findViewById(R.id.display_net_1);
                    tvNET.setText(R.string.ok);
                    tvNET.setTextColor(getResources().getColor(R.color.green));
                    break;
                case NET_UI_FAIL:
                    flog.append("\nNET___DONE,");
                    time = System.currentTimeMillis();
                    flog.append(time);
                    tvNET = (TextView) findViewById(R.id.display_net_1);
                    tvNET.setText(R.string.failed);
                    tvNET.setTextColor(getResources().getColor(R.color.red_dark));
                    adjustScore(msg.what);
                    break;
                case DNS_UI_DONE:
                    flog.append("\nDNS___DONE,");
                    time = System.currentTimeMillis();
                    flog.append(time);
                    TextView tvDNS = (TextView) findViewById(R.id.display_dns_1);
                    tvDNS.setText(R.string.dis_sec_undetected);
                    tvDNS.setTextColor(getResources().getColor(R.color.green));
                    break;
                case DNS_UI_FAIL:
                    flog.append("\nDNS___DONE,");
                    time = System.currentTimeMillis();
                    flog.append(time);
                    tvDNS = (TextView) findViewById(R.id.display_dns_1);
                    tvDNS.setText(R.string.dis_sec_detected);
                    tvDNS.setTextColor(getResources().getColor(R.color.red_dark));
                    adjustScore(msg.what);
                    break;
                case ARP_UI_DONE:
                    flog.append("\nARP___DONE,");
                    time = System.currentTimeMillis();
                    flog.append(time);
                    TextView tvARP = (TextView) findViewById(R.id.display_arp_1);
                    tvARP.setText(R.string.dis_sec_undetected);
                    tvARP.setTextColor(getResources().getColor(R.color.green));
                    break;
                case ARP_UI_FAIL:
                    flog.append("\nARP___DONE,");
                    time = System.currentTimeMillis();
                    flog.append(time);
                    tvARP = (TextView) findViewById(R.id.display_arp_1);
                    tvARP.setText(R.string.dis_sec_detected);
                    tvARP.setTextColor(getResources().getColor(R.color.red_dark));
                    adjustScore(msg.what);
                    break;
                case CURL_UI_DONE:
                    flog.append("\nPROB__DONE,");
                    time = System.currentTimeMillis();
                    flog.append(time);
                    tv = (TextView) findViewById(R.id.display_model_1);
                    tv.setText(model);
                    btn_f = FSA_MODEL;
                    S_FSA();
                    break;
                case AKB_UI_DONE:
                    btn_f = FSA_NMAP_DONE;
                    flog.append("\nAKB___DONE,");
                    time = System.currentTimeMillis();
                    flog.append(time);
                    details.setText(R.string.btn_Details);
                    S_FSA();
                    break;
                case AKB_UI_FAILED:
                    btn_f = FSA_NMAP_READY;
                    flog.append("\nAKB___DONE,");
                    time = System.currentTimeMillis();
                    flog.append(time);
                    tv = (TextView)findViewById(R.id.display_display_0);
                    tv.setText(R.string.nmap_Run);
                    S_FSA();
                    break;
                case THREAD_ERROR:
                    System.out.println("Thread Error");
                    break;
                default:
                    try {
                        Bundle data = msg.getData();
                        String val = data.getString("value");
                        Log.i("Result: ", val);
                    } catch (Exception e) { Log.e("error","Error",e);}
                    break;
            }
        }
    };
    private void adjustScore(int handerMess) {
        switch(handerMess) {
            case NET_UI_FAIL:
                check_Score += 200;
                getFinalScore();
                break;
            case DNS_UI_FAIL:
                check_Score += 400;
                getFinalScore();
                break;
            case ARP_UI_FAIL:
                check_Score += 300;
                getFinalScore();
                break;
            default:
                break;
        }
    }
    public void goToDetails() {
        Intent intent = new Intent( MainActivity.this, Details.class);
        Bundle bundle = new Bundle();
        bundle.putString("fout", fout);
        intent.putExtras(bundle);
        startActivity(intent);
    }
    /*
    *   fint is not 1
    *   Process the Nmap data to get the service information and search the VKB
    */
    private void dataProcess() {
        try {
            String str = "SSID: %1$S\nBSSID: %2$S\nYour IP: %3$S\nGateway: %4$S\nLocation: %5$S\nModel: %6$S\n";
            String strr = String.format( str, ssid, bssid, ip, gatewayIP, position, model);
            StringBuilder res = new StringBuilder(strr + "\n" + "Device MAC: " + address + "\n");
            res.append("\nPort#\tService\tVersion\tScore\n");
            if( fnmap != null) {
                String[] qs = fnmap.split("\n");
                for (String q : qs) {
                    if (q.contains("/tcp") && q.contains("open")) { //Get the score for each port
                        res.append(searchKeywords(q));
                        res.append("\n");
                    } else if (q.contains("Service Info:")) { //Get the score for the OS
                        res.append(q);
                        res.append("\n");
                    }
                }
                res.append("\n\n=== Nmap ===\n");
                res.append(fnmap);
            }
            if( fcurl != null) {
                res.append("\n\n=== CURL ===\n");
                res.append(fcurl);
            }
            fout = "Final Score: " + sum_Score + "\n\n=== Details ===\n" + res.toString();
            check_Score += sum_Score;
            getFinalScore();
        } catch (Exception e) {
            e.printStackTrace();
            Log.e("error", "Error: ", e);
            System.out.println("Error");
        }
        new Thread(runnableWriteLog).start();
        //new Thread(runnableSend).start();
    }
    private String intToIp( int i) {
        return (i & 0xFF ) + "." + ((i >> 8 ) & 0xFF) + "." + ((i >> 16 ) & 0xFF) + "." + ( i >> 24 & 0xFF) ;
    }
    @SuppressWarnings("deprecation")
    public void getWiFiInfo() {
        WifiManager wifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        if( !wifiManager.isWifiEnabled()) {
            wifiManager.setWifiEnabled(true);
        }
        WifiInfo wifiInfo = wifiManager.getConnectionInfo();

        DhcpInfo dhcp = wifiManager.getDhcpInfo();
        gatewayIP = Formatter.formatIpAddress(dhcp.gateway);
        ip = intToIp(wifiInfo.getIpAddress());
        ssid = wifiInfo.getSSID().replace("\"", "");
        bssid = wifiInfo.getBSSID();
        address = wifiInfo.getMacAddress();


        TextView tv0 = (TextView) findViewById(R.id.display_wifi_1);
        tv0.setText(ssid);

        List<ScanResult> networkList = wifiManager.getScanResults();
        System.out.println(networkList);
        if (networkList != null) {
            for (ScanResult network : networkList)
            {
                String Capabilities = network.capabilities;
                Log.w ("System.out", network.SSID + " capabilities : " + Capabilities);
                if( network.SSID.equals(ssid)) {
                    TextView tv1 = (TextView) findViewById(R.id.display_wep_1);
                    if( Capabilities.contains("WPA")) {
                        tv1.setText(R.string.dis_sec_wpa);
                        tv1.setTextColor(getResources().getColor(R.color.green));
                    } else if( Capabilities.contains("WEP")) {
                        tv1.setText(R.string.dis_sec_wep);
                        tv1.setTextColor(getResources().getColor(R.color.yellow));
                    } else {
                        tv1.setText(R.string.dis_sec_none);
                        tv1.setTextColor(getResources().getColor(R.color.red_dark));
                    }

                }
            }
        }

        flog.append("Start");
        fname = "LOG_" + bssid.replace( ":", "").toUpperCase() + ".txt";
        String[] qs = gatewayIP.split("\\.");
        if( qs.length == 4) {
            int ip1 = Integer.parseInt(qs[0]);
            int ip2 = Integer.parseInt(qs[1]);
            if ((ip1 == 10) || ((ip1 == 192) && (ip2 == 168)) || ((ip1 == 172) && (ip2 >= 16) && (ip2 < 32))) {
                btn_f = FSA_MODEL_RUNING;
                TextView tv = (TextView)findViewById(R.id.display_display_0);
                tv.setText(R.string.nmap_IPConfirmed);
                new Thread(runnableCurl).start();
                new Thread(runnableNet).start();
                new Thread(runnableDNS).start();
                new Thread(runnableARP).start();
            } else {
                System.out.println(R.string.warning_notLAN);
            }
        } else {
            System.out.println(R.string.warning_invalidIP);
        }
    }
    private static int btn_f;
    private final int FSA_START = 0;
    private final int FSA_MODEL = 1;
    private final int FSA_NMAP_READY = 2;
    private final int FSA_NMAP_RUNNING = 3;
    private final int FSA_NMAP_DONE = 4;
    private final int FSA_MODEL_RUNING = 5;
    private final int FSA_AKB_RUNNING = 6;
    private final int FSA_SETUP = 7;
    private final int FSA_SETUPING = 8;
    class RunnableSetupNmap implements Runnable {
        View view;
        public void setView(View newView) {
            view = newView;
        }
        public void run() {
            if (btn_f == FSA_SETUPING) {
                System.out.println("Setup: " + Test.extractFiles(view));
                handler.sendEmptyMessageDelayed( SETUP_FINISHED, 0);
            }
        }
    }
    RunnableSetupNmap runnableSetupNmap = new RunnableSetupNmap();
    public void hitButton(View view) {
        if( btn_f == FSA_SETUP) {
            btn_f = FSA_SETUPING;
            runnableSetupNmap.setView(view);
            new Thread(runnableSetupNmap).start();
        } else if( btn_f == FSA_START) {
            getWiFiInfo();
        } else if (btn_f == FSA_NMAP_DONE) {
            goToDetails();
        }
    }
    /*
    *   FSA Changing, no need to hit the button.
    */
    private void S_FSA() {
        if( btn_f == FSA_START) {
            getWiFiInfo();
        }
        if( btn_f == FSA_MODEL) {
            btn_f = FSA_AKB_RUNNING;
            new Thread(runnableAKB).start();
        }
        if( btn_f == FSA_NMAP_READY) {
            Button details = (Button)findViewById(R.id.btn_details);
            details.setText(R.string.btn_Run);
            btn_f = FSA_NMAP_RUNNING;
            String str = "SSID: %1$S\nBSSID: %2$S\nYour IP: %3$S\nGateway: %4$S\nLocation: %5$S\nModel: %6$S\n";
            String strr = String.format( str, ssid, bssid, ip, gatewayIP, position, model);
            StringBuilder res = new StringBuilder(strr + "\n" + "Device MAC: " + address + "\n");
            res.append("\nPort#\tService\tVersion\tScore\n");
            if( fcurl != null) {
                res.append("\n\n=== CURL ===\n");
                res.append(fcurl);
            }
            fout = "Final Score: " + sum_Score + "\n\n=== Details ===\n" + res.toString();
            new Thread(runnableSend).start();
            new Thread(runnableNmap).start();
        }
    }
    public void clear(View view) {
        salt = (int)System.currentTimeMillis();
        fname = "";
        fout = "";
        sum_Score = 0;
        check_Score = 0;
        flog = new StringBuffer();
        setContentView(R.layout.display);
        btn_f = FSA_SETUP;
        String[] testResult = Test.execShellStr("cd /data/data/com.netman.yukawa.safeap && ls").split("\n");
        int found = 0;
        for( String s : testResult) {
            System.out.println(s);
            if( s.compareTo("nmap") == 0) {
                ++found;
            } else if( s.compareTo("curl") == 0) {
                ++found;
            } else if( s.compareTo("busybox") == 0) {
                ++found;
            }
        }
        System.out.println(found);
        if( found > 2) {
            btn_f = FSA_START;
            TextView tv = (TextView)findViewById(R.id.display_display_0);
            tv.setText(R.string.setup_Done);
        }
        ip = "";
        ssid = "";
        bssid = "";
        gatewayIP = "";
        model = "";
        address = "";
        position = "";
    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        ContextWrapper c = new ContextWrapper(this);
        String appPath = c.getFilesDir().getPath();
        System.out.println(appPath);
        super.onCreate(savedInstanceState);
        setContentView(R.layout.display);
        salt = (int)System.currentTimeMillis();
        fname = "";
        fout = "";
        //send_Flag = 0;
        sum_Score = 0;
        check_Score = 0;
        flog = new StringBuffer();
        // Check if nmap has already been installed
        btn_f = FSA_SETUP;
        String[] testResult = Test.execShellStr("cd /data/data/com.netman.yukawa.safeap && ls").split("\n");
        int found = 0;
        for( String s : testResult) {
            System.out.println(s);
            if( s.compareTo("nmap") == 0) {
                ++found;
            } else if( s.compareTo("curl") == 0) {
                ++found;
            } else if( s.compareTo("busybox") == 0) {
                ++found;
            }
        }
        System.out.println(found);
        if( found > 2) {
            btn_f = FSA_START;
            TextView tv = (TextView)findViewById(R.id.display_display_0);
            tv.setText(R.string.setup_Done);
        }
    }
}