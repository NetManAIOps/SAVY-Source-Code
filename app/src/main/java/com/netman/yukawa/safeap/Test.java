package com.netman.yukawa.safeap;

import android.content.Context;
import android.content.res.AssetManager;
import android.net.DhcpInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.text.format.Formatter;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Spinner;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

import static com.netman.yukawa.safeap.R.id.spinner_mode;

public class Test extends AppCompatActivity {
    private TextView text_myip;
    private TextView text_gateway;

    private TextView myTextView;

    private List<String> list = new ArrayList<>();

    private String intToIp( int i) {
        return (i & 0xFF ) + "." +
                ((i >> 8 ) & 0xFF) + "." +
                ((i >> 16 ) & 0xFF) + "." +
                ( i >> 24 & 0xFF) ;
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
            Log.w("System.oeut", "CMD ERROR: " + e);
        }
        Log.w ("System.out", "CMD RES: " + retString);
        return retString;
    }
    @SuppressWarnings("deprecation")
    public void getGatewayIP( View view) {
        WifiManager wifiManager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
        if (!wifiManager.isWifiEnabled()) {
            wifiManager.setWifiEnabled(true);
        }
        WifiInfo wifiInfo = wifiManager.getConnectionInfo();
        DhcpInfo dhcp = wifiManager.getDhcpInfo();
        String gatewayIP = Formatter.formatIpAddress(dhcp.gateway);
        String ip = intToIp(wifiInfo.getIpAddress());
        String ssid = wifiInfo.getSSID();
        String bssid = wifiInfo.getBSSID();
        System.out.println("IP: " + ip);

        text_myip = (TextView) findViewById(R.id.myip);
        String str = getResources().getString(R.string.main_dispaly);
        String strr = String.format(str, ssid, bssid, ip, gatewayIP, "","");
        text_myip.setText(strr);

        String[] qs = ip.split("\\.");
        System.out.println(qs.length);
        text_gateway = (TextView) findViewById(R.id.gateway);
        if( qs.length != 4) {
            text_gateway.setText(R.string.warning_invalidIP);
        } else {
            System.out.println( qs[0] + " " + qs[1] + " " + qs[2] + " " + qs[3]);
            int ip1 = Integer.parseInt(qs[0]);
            int ip2 = Integer.parseInt(qs[1]);
            if ((ip1 == 10) || ((ip1 == 192) && (ip2 == 168)) || ((ip1 == 172) && (ip2 >= 16) && (ip2 < 32))) {
                text_gateway.setText(gatewayIP);
            } else {
                text_gateway.setText(R.string.warning_notLAN);
            }
        }
        System.out.println("Click");
    }
    private void WriteLogFile( StringBuffer Log, String filename) {
        String eol = System.getProperty("line.separator");
        try {
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter( openFileOutput( filename, 2)));
            text_myip = (TextView) findViewById(R.id.myip);
            writer.write( text_myip.getText().toString() + "\n" + Log.append(eol).toString());
            writer.close();
        } catch ( Exception e) {
            e.printStackTrace();
        }
    }
    public void test_button( View view) {
        //TextView t0 = (TextView) findViewById(R.id.test_t0);
        TextView t1 = (TextView) findViewById(R.id.test_t1);
        TextView t2 = (TextView) findViewById(R.id.test_t2);
        //String res0 = execShellStr( "cd /data/data/com.netman.yukawa.safeap && ls");
        String res1 = "Term: " + execShellStr( "cd /data/data/jackpal.androidterm/nmap && ls");
        String res2 = "Sdcard: " + execShellStr( "cd /sdcard/opt/nmap-6.46/bin && ls");
        //System.out.println(res0);
        System.out.println(res1);
        System.out.println(res2);
        //t0.setText(res0);
        t1.setText(res1);
        t2.setText(res2);
    }
    public void clean_test( View view) {
        TextView t0 = (TextView) findViewById(R.id.test_t0);
        TextView t1 = (TextView) findViewById(R.id.test_t1);
        TextView t2 = (TextView) findViewById(R.id.test_t2);
        t0.setText("");
        t1.setText("");
        t2.setText("");
    }
    public void nmap( View view) {
        text_gateway = (TextView) findViewById(R.id.gateway);
        String ip = text_gateway.getText().toString();
        System.out.println("Get IP: " + ip);
        TextView text_cmd = (TextView) findViewById(R.id.cmd);
        String cmdRes;
        if( ip.equals("IP ADDR ERROR.") || ip.equals("Not LAN IP ADDR.") || ip.equals("")) {
            text_cmd.setText(R.string.warning_invalidIP);
        } else {
            myTextView = (TextView) findViewById(R.id.nmap_type);
            int type = Integer.parseInt(myTextView.getText().toString());
            switch (type) {
                case 1:
                    cmdRes = execShellStr( "cd /data/data/com.netman.yukawa.safeap/ && ./nmap -T4 -sV -Pn -A -p22,80 --script=vuln " + ip);
                    break;
                case 2:
                    cmdRes = execShellStr( "cd /data/data/com.netman.yukawa.safeap/ && ./nmap -T4 -sV -Pn -p1-10000 " + ip);
                    break;
                case 3:
                    cmdRes = execShellStr( "cd /data/data/com.netman.yukawa.safeap/ && ./nmap -T4 -sV -Pn -p80 " + ip);
                    break;
                case 5:
                    cmdRes = execShellStr( "cd /data/data/com.netman.yukawa.safeap/ && ./nmap -T4 -sV -Pn -A --script=vuln " + ip);
                    break;
                default:
                    cmdRes = "";
            }
            System.out.println("CMD: " + cmdRes);
            text_cmd.setText(cmdRes);
            String now = ( new Timestamp(System.currentTimeMillis())).toString().replaceAll( " ", "_");
            String filename = "LOG_" + now + ".txt";
            WriteLogFile( new StringBuffer(cmdRes), filename);
            cmdRes = execShellStr( "cat /data/data/com.netman.yukawa.safeap/files/" + filename + " > /sdcard/SafeAP/" + filename);
            TextView t0 = (TextView) findViewById(R.id.test_t0);
            t0.setText(cmdRes);
        }
    }
    public void init_setup(View view) {
        TextView t0 = (TextView) findViewById(R.id.test_t0);
        t0.setText(extractFiles(view));
    }

    public static String extractFiles(View view) {
        String cmdRes;
        cmdRes = execShellStr("mkdir /sdcard/SafeAP");
        cmdRes += execShellStr("mkdir /sdcard/opt/nmap-6.46");
        cmdRes += execShellStr("chmod 777 /sdcard/SafeAP");
        cmdRes += copyNmapToSdCard(view);
        cmdRes += execShellStr("cat /sdcard/opt/nmap-6.46/bin/nmap > /data/data/com.netman.yukawa.safeap/nmap");
        cmdRes += execShellStr("chmod 777 /data/data/com.netman.yukawa.safeap/nmap");
        cmdRes += execShellStr( "cd /data/data/com.netman.yukawa.safeap/ && ./nmap --script-updatedb");
        return cmdRes;
    }

    private void WriteConfig( int mode) {
        System.out.println(mode);
        try {
            String eol = System.getProperty("line.separator");
            StringBuffer Log = new StringBuffer(""+mode);
            System.out.println(Log.toString());
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter( openFileOutput( "config.txt", 2)));
            writer.write(Log.append(eol).toString());
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
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
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.test);


        //final State appState = ((State) getApplicationContext());

        list.add("Mode 0: Default");
        list.add("Mode 1: Run Nmap For All Targets");
        list.add("Mode 2: No Nmap Test");
        list.add("Mode 3: Debug");
        list.add("Mode 4: Curl LOG");
        list.add("Mode 5: Run Nmap");
        myTextView = (TextView) findViewById(R.id.nmap_type);
        Spinner mySpinner = (Spinner) findViewById(spinner_mode);
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item, list);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        mySpinner.setAdapter(adapter);
        int state = ReadConfig();
        System.out.println(state);
        mySpinner.setSelection(state);

        mySpinner.setOnItemSelectedListener(new Spinner.OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> arg0, View arg1, int arg2, long arg3) {
                String str = getResources().getString(R.string.display_num);
                String strr = String.format(str, arg2);
                myTextView.setText(strr);
                //System.out.println("Selected: " + arg2);
                //appState.setState(arg2);
                WriteConfig(arg2);
                arg0.setVisibility(View.VISIBLE);
            }

            public void onNothingSelected(AdapterView<?> arg0) {
                myTextView.setText(R.string.display_none);
                arg0.setVisibility(View.VISIBLE);
            }
        });
        /*下拉菜单弹出的内容选项触屏事件处理*/
        mySpinner.setOnTouchListener(new Spinner.OnTouchListener() {
            public boolean onTouch(View v, MotionEvent event) {
                // TODO Auto-generated method stub
                /**
                 *
                 */
                return false;
            }
        });
        /*下拉菜单弹出的内容选项焦点改变事件处理*/
        mySpinner.setOnFocusChangeListener(new Spinner.OnFocusChangeListener() {
            public void onFocusChange(View v, boolean hasFocus) {
                // TODO Auto-generated method stub

            }
        });
    }

    private static String copyNmapToSdCard(View view) {
        String result = new String();
        result += copyFileOrDir("nmap.tgz", "/sdcard/opt/nmap-6.46/", view);
        result += copyFileOrDir("busybox", "/data/data/com.netman.yukawa.safeap/", view);
        result += copyFileOrDir("curl", "/data/data/com.netman.yukawa.safeap/", view);
        result += execShellStr("chmod 777 /data/data/com.netman.yukawa.safeap/busybox");
        result += execShellStr("chmod 777 /data/data/com.netman.yukawa.safeap/curl");
        execShellStr("chmod 777 /sdcard/opt/nmap-6.46");
        result += execShellStr("cd /data/data/com.netman.yukawa.safeap/ && ./busybox tar zxvf /sdcard/opt/nmap-6.46/nmap.tgz -C /sdcard/opt/nmap-6.46/");
        return result;
    }

    private static String copyFileOrDir(String sourcePath, String targetPath, View view) {
        String result = new String();
        AssetManager assetManager = view.getContext().getAssets();
        String assets[] = null;
        try {
            //Log.i("tag", "copyFileOrDir() " + sourcePath);
            result += "copyFileOrDir() " + sourcePath + "\n";
            (new File(targetPath)).mkdirs();
            assets = assetManager.list(sourcePath);
            if (assets.length == 0) {
                result += copyFile(sourcePath, targetPath, view);
            } else {
                // String fullPath =  TARGET_BASE_PATH + path;
                String fullPath = targetPath;
                //Log.i("tag", "path=" + fullPath);
                result += "path=" + fullPath + "\n";
                File dir = new File(fullPath);
                if (!dir.exists() && !sourcePath.startsWith("images") && !sourcePath.startsWith("sounds") && !sourcePath.startsWith("webkit")) {
                    if (!dir.mkdirs()) {
                        //Log.i("tag", "could not create dir " + fullPath);
                        result += "could not create dir " + fullPath + "\n";

                    }
                }
                for (String asset : assets) {
                    String p;
                    if (sourcePath.equals(""))
                        p = "";
                    else
                        p = sourcePath + "/";

                    if (!sourcePath.startsWith("images") && !sourcePath.startsWith("sounds") && !sourcePath.startsWith("webkit"))
                        result += copyFileOrDir(p + asset, targetPath + asset, view);
                }
            }
        } catch (IOException ex) {
            //Log.e("tag", "I/O Exception", ex);
            result += "I/O Exception" + "\n";
        }
        return result;
    }

    private static String copyFile(String filename, String destPath, View view) {
        String result = new String();
        AssetManager assetManager = view.getContext().getAssets();
        /*
        try {
            for (String str : assetManager.list("")) {
                result += str + "\n";
            }
        } catch (Exception e) {}
        */
        InputStream in = null;
        OutputStream out = null;
        String newFileName = null;
        try {
            //Log.i("tag", "copyFile() " + filename);
            result += "copyFile() " + filename + "\n";
            in = assetManager.open(filename);
            if (filename.endsWith(".jpg")) // extension was added to avoid compression on APK file
                newFileName = destPath + filename.substring(0, filename.length() - 4);
            else
                newFileName = destPath + filename;
            out = new FileOutputStream(newFileName);

            byte[] buffer = new byte[1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            in.close();
            in = null;
            out.flush();
            out.close();
            out = null;
        } catch (Exception e) {
            //Log.e("tag", "Exception in copyFile() of " + newFileName);
            result += "Exception in copyFile() of " + newFileName + "\n";
            //Log.e("tag", "Exception in copyFile() " + e.toString());
            result += "Exception in copyFile() " + e.toString() + "\n";
        }
        return result;
    }
}