package com.netman.yukawa.safeap;

import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.DhcpInfo;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiConfiguration;
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
import java.net.URL;
import java.net.URLEncoder;
import java.util.List;

public class Display extends AppCompatActivity {
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

    private final int MODELSTATE_NORMAL = 0;
    private final int MODELSTATE_NMAP_ALWAYS_SCAN = 1;
    private final int MODELSTATE_NO_NMAP_SCAN = 2;

    private static int send_Flag = 0;
    private static int retrans = 5; //Retransmission times
    private static String fout;
    private static String fname;
    private static String fdata;
    private static String fnmap;
    private static String fcurl;
    private static String flog;
    private static String errorlog;

    private String ip;
    private String ssid;
    private String bssid;
    private String gatewayIP;
    private String model;
    private String address;
    private String position;

    private static int fint;
    private static int state;

    private int salt;

    private static String fsend;

    private static int ver1;
    private static int ver2;
    private static int ver3;
    private static int ver4;

    private static int sum_Score;

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
                int cnt = 1;
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
                StringBuffer version = new StringBuffer();
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
        System.out.println(sum_Score);
        //TextView myTextView = (TextView) findViewById(R.id.display_display);
        TextView myTextView1 = (TextView) findViewById(R.id.display_display_1);

        int score = normalization(sum_Score) / 10;
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
        //System.out.println(cmd);
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
    /*Send the result to our server
        send_Flag: FSA State
        0   state
        1   sending
        2   done
    */
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
    }
    Runnable runnableSend = new Runnable(){
        @Override
        public void run() {
            try {
                String content = flog + "\n\n" + fsend + "\n\n=== CURL ===\n" + fcurl + "\n\n=== ERRLOG ===\n" + errorlog + "\n";
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
            if( fint > 0) {
                WriteLogFile(new StringBuffer("filename="+fname+"&content="+flog+"\n\n"+fout), fname);
            } else {
                WriteLogFile(new StringBuffer("filename="+fname+"&content="+flog+"\n\n"+fout+"\n\n"+errorlog), fname);
            }
            execShellStr("cat /data/data/com.netman.yukawa.safeap/files/" + fname + " > /sdcard/SafeAP/" + fname);
            execShellStr("rm /data/data/com.netman.yukawa.safeap/files/" + fname);
            handler.sendEmptyMessageDelayed(WRITE_FILE_DONE, 0);
        }
    };
    Runnable runnableNmap = new Runnable(){
        @Override
        public void run() {
            int check_salt = salt;
            System.out.println("Nmap Running");
            flog += "\nNMAP_START,";
            long time = System.currentTimeMillis();
            flog += time;
            fnmap = execShellStr("cd /data/data/com.netman.yukawa.safeap/ && ./nmap -T4 -sV -Pn -p22,23,53,80,443,1900,8000,8080 " + gatewayIP);
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
            flog += "\nNET__START,";
            long time = System.currentTimeMillis();
            flog += time;
            //Process here
            try {
                URL url = new URL("http://www.baidu.com");
                HttpURLConnection connection = (HttpURLConnection)url.openConnection();
                connection.setRequestMethod("GET");
                connection.setRequestProperty("User-Agent", "Mozilla/5.0");
                connection.connect();
                connection.getInputStream();
                int responseCode = connection.getResponseCode();
                System.out.println("Baidu Response Code: " + responseCode);
                if( check_salt == salt) {
                    if( responseCode == 200) {
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
            int check_salt = salt;
            System.out.println("NetCheck Running");
            flog += "\nNET__START,";
            long time = System.currentTimeMillis();
            flog += time;
            //TODO: Process here

            if( check_salt == salt) {
                handler.sendEmptyMessageDelayed( DNS_UI_DONE, 0);
            } else {
                handler.sendEmptyMessageDelayed( EXPIRED, 0);
            }
        }
    };
    Runnable runnableARP = new Runnable(){
        @Override
        public void run() {
            int check_salt = salt;
            System.out.println("NetCheck Running");
            flog += "\nNET__START,";
            long time = System.currentTimeMillis();
            flog += time;
            //TODO: Process here
            try {
                BufferedReader br = new BufferedReader(new FileReader("/proc/net/arp"));
                String line = "";
                while((line = br.readLine()) != null) {
                    Log.w("System.out",line);
                    // The ARP table has the form:
                    //   IP address        HW type    Flags     HW address           Mask   Device
                    //   192.168.178.21    0x1        0x2       00:1a:2b:3c:4d:5e    *      tiwlan0
                }
                br.close();
            }
            catch(Exception e) { Log.e("error", "Error: ", e); }
            if( check_salt == salt) {
                handler.sendEmptyMessageDelayed( ARP_UI_DONE, 0);
            } else {
                handler.sendEmptyMessageDelayed( EXPIRED, 0);
            }
        }
    };
    @SuppressWarnings("HandlerLeak")
    private Handler handler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            super.handleMessage(msg);
            switch (msg.what) {
                case SETUP_FINISHED:
                    btn_f = FSA_START;
                    runFSA_START();
                    break;
                case UPDATE_UI_FAILED:
                    send_Flag = 0;
                    if( retrans > 0) {
                        retrans --;
                        new Thread(runnableSend).start();
                    }
                    break;
                case UPDATE_UI_DONE:
                    send_Flag = 2;
                    break;
                case WRITE_FILE_DONE:
                    send_Flag = 0;
                    new Thread(runnableSend).start();
                    break;
                case NMAP_UI_DONE:
                    btn_f = FSA_NMAP_DONE;
                    dataProcess();
                    Button details = (Button)findViewById(R.id.btn_details);
                    details.setText(R.string.btn_Details);
                    break;
                case NET_UI_DONE:
                    setText_2( 1, 2);
                    break;
                case NET_UI_FAIL:
                    setText_2( 0, 2);
                    break;
                default:
                    Bundle data = msg.getData();
                    String val = data.getString("value");
                    Log.i("Result: ", val);
                    break;
            }
        }
    };
    /*
    *   Set the Text for Internet Access Check.
    *   f: indicator for the result. 0 for failed, 1 for OK
    *   n: for which textview. 2 for Internet, 3 for DNS, 4 for ARP
    */
    @SuppressWarnings("deprecation")
    private void setText_2( int f, int n) {
        TextView tv;
        switch (n) {
            case 2:
                tv = (TextView) findViewById(R.id.display_net_1);
                break;
            case 3:
                tv = (TextView) findViewById(R.id.display_dns_1);
                break;
            case 4:
                tv = (TextView) findViewById(R.id.display_arp_1);
                break;
            default:
                return;
        }
        if( f == 1) {
            tv.setText(R.string.ok);
            tv.setTextColor(getResources().getColor(R.color.green));
        } else {
            tv.setText(R.string.failed);
            tv.setTextColor(getResources().getColor(R.color.red_dark));
        }
    }
    public void goToDetails() {
        Intent intent = new Intent( Display.this, Details.class);
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
            fdata = strr + "\n" + "Device MAC: " + address + "\n";
            StringBuffer res = new StringBuffer(fdata);
            res.append("\nPort#\tService\tVersion\tScore\n");
            if( fnmap != null) {
                String[] qs = fnmap.split("\n");
                if( qs.length <= 1) {
                    //myTextView.setText(R.string.display_maindisplay_invalid);
                }
                for (String q : qs) {
                    if (q.contains("/tcp")) { //Get the score for each port
                        res.append(searchKeywords(q));
                        res.append("\n");
                    } else if (q.contains("Service Info:")) { //Get the score for the OS
                        res.append(q);
                        res.append("\n");
                    }
                }
            }
            fsend = "Final Score: " + sum_Score + "\n" + res.toString();
            if( state >= 0) {
                if( fnmap != null) {
                    res.append("\n\n=== Nmap ===\n");
                    res.append(fnmap);
                }
                if( fcurl != null) {
                    res.append("\n\n=== CURL ===\n");
                    res.append(fcurl);
                }
            }
            fout = "Final Score: " + sum_Score + "\n\n=== Details ===\n" + res.toString();
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

        List<ScanResult> networkList = wifiManager.getScanResults();
        if (networkList != null) {
            for (ScanResult network : networkList)
            {
                String Capabilities = network.capabilities;
                //Log.w ("System.out", network.SSID + " capabilities : " + Capabilities);
                if( network.SSID.toString().equals(ssid)) {
                    TextView tv1 = (TextView) findViewById(R.id.display_wep_1);
                    tv1.setText(Capabilities);
                }
            }
        }

        String[] qs = gatewayIP.split("\\.");
        if( qs.length == 4) {
            int ip1 = Integer.parseInt(qs[0]);
            int ip2 = Integer.parseInt(qs[1]);
            if ((ip1 == 10) || ((ip1 == 192) && (ip2 == 168)) || ((ip1 == 172) && (ip2 >= 16) && (ip2 < 32))) {

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
                Test.extractFiles(view);
                handler.sendEmptyMessageDelayed( SETUP_FINISHED, 0);
            }
        }
    }

    RunnableSetupNmap runnableSetupNmap = new RunnableSetupNmap();

    private void runFSA_START() {
        Button details = (Button)findViewById(R.id.btn_details);
        details.setText(R.string.btn_Run);
        new Thread(runnableNmap).start();
        new Thread(runnableNet).start();
    }
    public void hitButton(View view) {
        if( btn_f == FSA_SETUP) {
            btn_f = FSA_SETUPING;
            runnableSetupNmap.setView(view);
            new Thread(runnableSetupNmap).start();
        } else if( btn_f == FSA_START) {
            runFSA_START();
        } else if (btn_f == FSA_NMAP_DONE) {
            goToDetails();
        }
    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.display);
        salt = (int)System.currentTimeMillis();
        send_Flag = 0;
        sum_Score = 0;
        // Check if nmap has already been installed
        btn_f = FSA_SETUP;
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
            btn_f = FSA_START;
        }

        getWiFiInfo();
        TextView tv1 = (TextView) findViewById(R.id.display_wifi_1);
        tv1.setText(ssid);
    }
}