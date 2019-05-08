package com.secura.sipwatcher;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.support.constraint.ConstraintLayout;
import android.support.design.widget.NavigationView;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v4.content.LocalBroadcastManager;
import android.support.v4.view.GravityCompat;
import android.support.v4.widget.DrawerLayout;
import android.support.v7.app.ActionBarDrawerToggle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.ExpandableListView;
import android.widget.TextView;
import android.widget.Toast;
import com.secura.sipwatcher.ipsec.IPsecStateManager;
import com.secura.sipwatcher.ipsec.SA;
import com.secura.sipwatcher.services.CentralIntelligence;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The main activity
 * Checks if the phone is VoLTE compatible & sets up the device if needed.
 * Then it can initiate a capture, which then displays SIP message that travel through the phone.
 * Tested with a Samsung Galaxy A3 2017 (SM-A320FL)
 */
public class MainActivity extends AppCompatActivity
        implements NavigationView.OnNavigationItemSelectedListener {

    // Enable or disables debug messages
    // Please note that StrategicCommand.debug_print() and CentralIntelligence.debug_print() also holds a debug boolean
    static private final boolean _DEBUG = false; // note: this value is not yet used system-wide. e.g. StrategicCommand.java has its own debug boolean, yes sorry... #todo

    // View elements.
    private Button           _btnVerify,
                             _btnCaptureStart;
    private TextView         _txtRmnetInf,
                             _txtTshark,
                             _txtTcpdump,
                             _txtSaCount,
                             _txtSaProto,
                             _txtSaMode,
                             _txtSaAuthCipher,
                             _txtSaAuthKey,
                             _txtSaEncrCipher,
                             _txtSaEncrKey;
    private ConstraintLayout _layoutContainer,
                             _layout1,
                             _layout2;

    // List view things
    private static ExpandableListAdapter         _listAdapter;
    private ExpandableListView                   _expListView;
    private static List<String>                  _listDataHeader;
    private static HashMap<String, List<String>> _listDataChild;

    // Check to see if the user has pressed the initial button before automating things.
    private boolean _userHasStarted = false;

    // The file location of verious binaries
    private Map<String, String> _binaryLocations;

    // Intent & receiver to detect airplane mode state changes
    private IntentFilter      _ifAirplane = null;
    private BroadcastReceiver _brAirplane = null;

    private IntelligenceReceiver ir;

    // Keep track of our running capture state
    private volatile boolean _isThreadRunning = false;

    // Keep track of own IP to differentiate the IP of the SIP proxy.
    private InetAddress _rmnet_ip = null;

    // Keep track of one Security Association (SA) of IPsec
    private SA[] _sa = new SA[4];

    // Keeps track of the amount of SIP messages received through our BroadcastReceiver IntelligenceReceiver
    private static int _brifCounter = 0;

    // A UI handler to update the GUI from a static referrence
    private static Handler UIHandler = new Handler(Looper.getMainLooper());

    // Our intent object to send data to our background service
    private Intent _ci = null;

    // Default state is verify.
    private enum States {VERIFY, CAPTURE}
    private States state = States.VERIFY;

    // To determine if airplane mode is on or off.
    private boolean _isAirplaneModeOn;

    // To prevent double registering through the onResume function which causes an exception @ onDestroy
    private boolean receiversRegistered;





    // If true, it will read /sdcard/capture2.pcap instead of from an interface
    // String instead of a boolean due to how the data is received by the background service
    private String  useLocalPcap    = "false";   // a String instead of a Boolean because this value is passed through an intent, which does not seem to accept boolean values...
                                                // Note: change 'localPcapLocation' in CentralIntelligence.java as well
    private String  volteInterface  = "rmnet1"; // note: change StrategicCommand.java:135 as well. todo send interface name to service
    private int     sa_count_pcap   = 4;        // when using a local pcap, define here the amount of (IPsec) SA's there were at the moment of capture (default: 4)





    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

//        FloatingActionButton fab = findViewById(R.id.fab);
//        fab.setOnClickListener(new View.OnClickListener() {
//            @Override
//            public void onClick(View view) {
//                Snackbar.make(view, "Hi!", Snackbar.LENGTH_LONG)
//                        .setAction("Action", null).show();
//            }
//        });

        DrawerLayout drawer = findViewById(R.id.drawer_layout);
        ActionBarDrawerToggle toggle = new ActionBarDrawerToggle(
                this, drawer, toolbar, R.string.navigation_drawer_open, R.string.navigation_drawer_close);
        drawer.addDrawerListener(toggle);
        toggle.syncState();

        NavigationView navigationView = findViewById(R.id.nav_view);
        navigationView.setNavigationItemSelectedListener(this);

        // ********************************************************************

        _btnVerify       = findViewById(R.id.btn1);
        _btnCaptureStart = findViewById(R.id.btn2);
        _txtRmnetInf     = findViewById(R.id.value_1);
        _txtTshark       = findViewById(R.id.value_2);
        _txtTcpdump      = findViewById(R.id.value_3);
        _txtSaCount      = findViewById(R.id.value_4);
        _txtSaProto      = findViewById(R.id.value_5);
        _txtSaMode       = findViewById(R.id.value_6);
        _txtSaAuthCipher = findViewById(R.id.value_7);
        _txtSaAuthKey    = findViewById(R.id.value_8);
        _txtSaEncrCipher = findViewById(R.id.value_9);
        _txtSaEncrKey    = findViewById(R.id.value_10);

        _layoutContainer = findViewById(R.id.layout_main_contraint);
        _layout1         = findViewById(R.id.layout_in_main_1);
        _layout2         = findViewById(R.id.layout_in_main_2);

        _expListView     = findViewById(R.id.lvExp);

        // Store the location of certain binaries.
        _binaryLocations = new HashMap<>();

        // Detect airplane mode
        _enableAirplaneModeDetection();

        // preparing list data to hold SIP messages
        _listDataHeader = new ArrayList<>();
        _listDataChild  = new HashMap<>();
        _listAdapter    = new ExpandableListAdapter(this, _listDataHeader, _listDataChild);
        _expListView.setAdapter(_listAdapter);

        // Register our receiver to listen for data from background service
                     ir     = new IntelligenceReceiver();
        IntentFilter filter = new IntentFilter(CentralIntelligence.ACTION);
        LocalBroadcastManager.getInstance(this).registerReceiver(ir, filter);

        receiversRegistered = true;
    }

    /**
     * Onclick event listener of the VoLTE button in the main activity.
     *
     * @param view View  The current activity view or button pressed?
     */
    public final void onclickBtnVolteCompat(View view)
    {
        if (state != States.VERIFY)
        {
            debug_print("[onclickBtnVolteCompat]: Warning: called in wrong state, stopping...");
            return;
        }

        // Register the first onclick event of user.
        _userHasStarted = true;

        // The following thread construction is used to control GUI updates
        // In normal circumstances, the GUI thread updates the GUI after the function finishes
        // Therefore, we need to create a new thead, and run runOnUiThread inside it.
        new Thread() {
            public void run() {
                boolean error    = false;
                int     sa_count;

                // Provide feedback
                _updateGuiBtn(_btnVerify,"Loading...",false, R.color.colorAccent, View.VISIBLE,0);

                // rmnet interface
                if(useLocalPcap.equals("true"))
                {
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            _txtRmnetInf.setText("Local pcap");
                            _txtRmnetInf.setTextColor(Color.argb(255, 255, 165, 0));
                        }
                    });
                } else {
                    _rmnet_ip = _getIP(volteInterface);
                    if(_rmnet_ip != null){
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                _txtRmnetInf.setText(_rmnet_ip.getHostAddress());
                                _txtRmnetInf.setTextColor(Color.GREEN);
                            }
                        });
                    } else {
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                _txtRmnetInf.setText("Unavailable");
                                _txtRmnetInf.setTextColor(Color.RED);
                            }
                        });
                        error = true;
                    }
                }


                // Check tshark & its libs
                if(_checkBinary("tshark", "skonarf")){
                    if(_checkTsharkLibs()){
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                _txtTshark.setText("Available");
                                _txtTshark.setTextColor(Color.GREEN);
                            }
                        });
                    } else {
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                _txtTshark.setText("Unavailable: missing library");
                                _txtTshark.setTextColor(Color.RED);
                            }
                        });
                        debug_print("[onclickBtnVolteCompat]: failed to setup tshark libraries");
                        error = true;
                    }
                } else {
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            _txtTshark.setText("Unavailable: tshark not found");
                            _txtTshark.setTextColor(Color.RED);
                        }
                    });
                    debug_print("[onclickBtnVolteCompat]: failed to setup tshark libraries");
                    error = true;
                }

                // Check tcpdump
                if(_checkBinary("tcpdump", "bigbrother")){
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            _txtTcpdump.setText("Available");
                            _txtTcpdump.setTextColor(Color.GREEN);
                        }
                    });
                } else {
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            _txtTcpdump.setText("Unavailable/not found");
                            _txtTcpdump.setTextColor(Color.RED);
                        }
                    });
                    error = true;
                }

                // Write access on SDcard?
                if(!mkdirOnSD()) {
                    error = true;
                    debug_print("[onclickBtnVolteCompat]: error: missing write permissions on SDcard.");
                }

                // IPsec SA
                sa_count = _getSaCount();
                _getSaSecDetails(sa_count);
                if(sa_count != 4){
                    error = true;
                    debug_print("[getSaSecDetails] Expected 4 SA's, found: " + sa_count);
                }

                // Reset button if no error
                if(!error || useLocalPcap.equals("true") ) {
                    // VoLTE requirements are all OK, change into capture mode.
                    state = States.CAPTURE;

                    _updateGuiBtn(_btnVerify,"Done, refresh?",true, R.color.colorSuccess, View.VISIBLE,100);
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }

                    _updateGuiBtn(_btnCaptureStart,"",true, 0, View.VISIBLE ,0);
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            _layout2.setVisibility(View.VISIBLE);
                        }
                    });
                } else {
                    _updateGuiBtn(_btnVerify,"Retry?",true, R.color.colorWarning, View.VISIBLE,100);
                    _updateGuiBtn(_btnCaptureStart,"",false, 0, View.INVISIBLE, 0);
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            _layout2.setVisibility(View.INVISIBLE);
                        }
                    });
                }
            }

        }.start();
    }


    /**
     * Called when the users clicks the capture button.
     * Initiates a background services to capture network traffic.
     *
     * @param view The GUI element which has been clicked on
     */
    public final void onclickStartCapture(View view) {
        debug_print("[onclickStartCapture]: started");

        if (state != States.CAPTURE){
            debug_print("[onclickStartCapture]: Warning: called in wrong state, stopping...");
            return;
        }

        if(_isAirplaneModeOn){
            _updateGuiBtn(_btnCaptureStart, "Check Airplaine mode", false, R.color.colorWarning, View.VISIBLE, 10);
            return;
        }

        // Start or stop service?
        if(_isThreadRunning || view == null){
            debug_print("[onclickStartCapture]: already running, stopping capture...");

            // Setting this to false, will halt the while loop which checks for new lines to read.
            _isThreadRunning = false;

            // Stop capturing...
            stopBackgroundService();
            return;

        } else {
            debug_print("[onclickStartCapture]: starting capture...");
            _isThreadRunning = true;

            // Provide feedback to the user that the capture is running.
            _updateGuiBtn(_btnCaptureStart, "Capturing... (stop?)", true, R.color.colorSuccess, View.VISIBLE, 0);

            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    _layout1.setVisibility(View.GONE);
                    _expListView.setVisibility(View.VISIBLE);
                    _layout1.forceLayout();
                    _expListView.requestLayout();
                }
            });
        }

        String ipVersion       = ((_rmnet_ip != null && _rmnet_ip.getAddress().length == 4) ? "IPv4" : "IPv6");
        String encrKey         = ((_sa[0].encryptionKey == null) ? "" : _sa[0].encryptionKey);
        String authKey         = ((_sa[0].authKey       == null) ? "" : _sa[0].authKey);
        String packetSeperator = "*****";
        String authAlgo        = "";
        String encrAlgo        = "";

        // when you use a local pcap from your sdcard, fill in these IPsec details below
        // A rooted samsung device can request this info with e.g.: the terminal command: ip xfrm state
        // the input pcap is stored on e.g.:  /sdcard/capture.pcap
        // input is defined in CentralIntelligence.java in variable 'localPcapLocation'
        if(useLocalPcap.equals("true") )
        {
            encrKey    = "";
            authKey    = "";
            encrAlgo   = "NULL"; // no encrytion used
            authAlgo   = "HMAC-MD5-96 [RFC2403]";
            ipVersion  = "IPv6";
            _sa[0].sport = "6301";
            _sa[1].sport = "6490";
            _sa[2].sport = "6301";
            _sa[3].sport = "6490";
        }
        else
        {
            // tshark requires the [RFC****] to be included with the algo's
            switch(_sa[0].authAlgorithm){
                case HMAC_MD5_96:
                    authAlgo =  "HMAC-MD5-96 [RFC2403]";
                    break;
                case HMAC_SHA1_96:
                    authAlgo = "HMAC-SHA1-96 [RFC2404]";
                    break;
                case NULL:
                default:
                    debug_print("[onclickStartCapture] Warning: IPsec authAlgo is set to NULL)");
                    authAlgo = "NULL";
            }
            switch(_sa[0].encryptionAlgorithm){
                case AES_CBC:
                    encrAlgo = "AES-CBC [RFC3602]";
                    break;
                case TRIPPLE_DES_CBC:
                    encrAlgo = "TripleDES-CBC [RFC2451]";
                    break;
                case NULL:
                default:
                    encrAlgo = "NULL"; // no encrytion used
            }
        }

        // Process environment such that the binaries (tshark) can find its required libraries
        // If you try to manually run the binary through e.g. ADB, then copy&past this export into your terminal
        // else error: CANNOT LINK EXECUTABLE "tshark": library "libwiretap.so" not found
        // todo improve cross-compile options for wireshark/tshark
        final String envp = "export LD_LIBRARY_PATH=/data/user/0/com.secura.sipwatcher/files";

        // Get the right tshark location.
        String tsharkLoc = ((_binaryLocations.get("tshark") != null)
                ? _binaryLocations.get("tshark")
                : _binaryLocations.get("arm-linux-androideabi-tshark"));

        // Create an intent
        _ci = new Intent(this, CentralIntelligence.class);

        // Pass the data to the background service
        _ci.putExtra("tsharkLoc",       tsharkLoc);
        _ci.putExtra("tcpdumpLoc",      _binaryLocations.get("tcpdump"));
        _ci.putExtra("encrKey",         encrKey);
        _ci.putExtra("authKey",         authKey);
        _ci.putExtra("encrAlgo",        encrAlgo);
        _ci.putExtra("authAlgo",        authAlgo);
        _ci.putExtra("ipVersion",       ipVersion);
        _ci.putExtra("envp",            envp);
        _ci.putExtra("packetSeperator", packetSeperator);
        _ci.putExtra("useLocalPcap",    useLocalPcap);
        _ci.putExtra("sport0",          _sa[0].sport);
        _ci.putExtra("sport1",          _sa[1].sport);
        _ci.putExtra("sport2",          _sa[2].sport);
        _ci.putExtra("sport3",          _sa[3].sport);
        if(useLocalPcap.equals("true")){
            _ci.putExtra("ipSrc", "127.0.0.1");
        } else {
            _ci.putExtra("ipSrc", _rmnet_ip.getHostAddress());
        }

        // Start service
        startService(_ci);

        // Lets wait for receiving broadcasts containing SIP messages.
        new Thread() {
            public void run() {
                int i = 1; // counter for the dots 'animation'

                while (_isThreadRunning) {
                    try {
                        Thread.sleep(1000);
                        i = (i+1) % 3;
                        String input = "" + new String(new char[i+1]).replace("\0", ".");

                        if(input.length() == 1)
                            input += "  ";
                        if(input.length() == 2)
                            input += " ";

                        _updateGuiBtn(_btnCaptureStart,"Capturing"+input+" (stop?)",true, 0, View.VISIBLE,0);

                    } catch (Exception e) {
                        debug_print("[onclickStartCapture] thread sleep?: " + e.getMessage());
                    }

                }

                // Provide feedback to the user that the capture is running.
                _updateGuiBtn(_btnCaptureStart,"Stopped, restart?",true, R.color.colorWarning, View.VISIBLE,0);
            }
        }.start();

        debug_print("[CentralIntelligence]: onclickStartCapture finished.");

    }

    /**
     * Sends an intent to the background service such that it stops its running process
     */
    private void stopBackgroundService() {
        // Setup an intent for the background service
        Intent in = new Intent(CentralIntelligence.ACTION_UDPATE);

        // set running to false, e.g. stop running.
        in.putExtra("setRunningState", "false");

        // Send to background service
        this.sendBroadcast(in);
    }

    /**
     * Checks & sets the required tshark libraries (only for our cross-compiled tshark binary)
     *
     * @return Boolean TRUE on success (libraries already exists or copied successfully), FALSE on failure.
     */
    private boolean _checkTsharkLibs(){

        if(_binaryLocations.get("tshark") != null){
            // If tshark itself is available, then we don't need to include our own cross-compiled libs
            debug_print("[checkTsharkLibs]: No need, tshark is already available");
            return true;
        }

        AssetManager am  = getAssets();
        InputStream in   = null;
        OutputStream out = null;

        debug_print("[checkTsharkLibs]: Getting assets...");

        // Try to get all assets
        try {
            String[] assets = am.list("");
            for (String asset : assets){

                if(asset == null)
                    continue;

                if(asset.isEmpty() || asset.equals("images"))
                    continue;

                if(asset.startsWith("lib") || asset.contains("ld-linux") ){
                    try {
                        // Check if file already exists
                        File file = new File(getFilesDir().getAbsolutePath()+"/" + asset);
                        if(!file.exists()) {

                            // Get file from assets
                            in = am.open(asset);
                            File outFile = new File(getFilesDir(), asset);
                            out = new FileOutputStream(outFile);

                            // Write file /data/user/0/<package_name>/files
                            byte[] buffer = new byte[in.available()];
                            int read;
                            while ((read = in.read(buffer)) != -1) {
                                out.write(buffer, 0, read);
                            }
                        }
                    } catch (Exception e) {
                        debug_print("[checkTsharkLibs]: failed setting library " + asset + ": " + e.getMessage());
                        return false;
                    } finally {
                        if (in != null) {
                            try {
                                in.close();
                            } catch (IOException e) { }
                        }
                        if (out != null) {
                            try {
                                out.close();
                            } catch (IOException e) { }
                        }
                    }
                } else {
                    debug_print("[checkTsharkLibs]: asset not allowed: " + asset);
                }

            } // for
        } catch (Exception e) {
            debug_print("[checkTsharkLibs]: Failed to setting required libraries " + e.getMessage());
            return false;
        }
        debug_print("[checkTsharkLibs]: done");
        return true;
    }

    /**
     * This functions checks if certain binaries are available.
     * Else it will try to copy the included binaries to the app's data directory and make it available.
     * Meanwhile, its stores the binary file location in the private var _binaryLocations
     *
     * @param  binaryName  String  The name of the binary, e.g. "tcpdump" or "tshark"
     * @param  stratComCmd String  The command name used within the globalOperations() to check for the binary
     * @return             Boolean TRUE on success (binary available), FALSE on failure.
     */
    private boolean _checkBinary(String binaryName, String stratComCmd){

        // Check if binary is available system wide, if so, save the location and return
        List<String> opsResults = StrategicCommand.globalOperations(stratComCmd);
        if(opsResults.size() == 1){
            _binaryLocations.put(binaryName, opsResults.get(0));
            return true;
        }

        debug_print("[checkBinary]:" + binaryName + " not available system wide..");

        // If tshark, change the name that indicates our cross-compiled version.
        if(binaryName.equals("tshark"))
            binaryName = "arm-linux-androideabi-tshark";

        // Check if the binary is available with the app data dir
        _binaryLocations.put(binaryName, getFilesDir().getAbsolutePath()+"/" + binaryName);
        File bin1 = new File(_binaryLocations.get(binaryName));
        if(bin1.exists() && bin1.canExecute() && bin1.length() > 0){
            debug_print("[checkBinary]:" + binaryName + " found in data dir");
            return true;
        }

        debug_print("[checkBinary]: installing " + binaryName + "..");

        // No binary available
        // Lets use our own binary (in assets dir), we need to copy it to a executable directory
        AssetManager assetManager = getAssets();
        InputStream in            = null;
        OutputStream out          = null;

        try {
            // Get bin
            in           = assetManager.open(binaryName);
            File outFile = new File(getFilesDir(), binaryName);
            out          = new FileOutputStream(outFile);

            // Write bin
            byte[] buffer = new byte[in.available()];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
        } catch (Exception e) {
            debug_print("failed to use own " + binaryName + " " + e.getMessage());
            return false;
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) { }
            }
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) { }
            }
        }

        // Check if our executable works
        File bin2 = new File(_binaryLocations.get(binaryName));
        bin2.setExecutable(true);
        if(bin2.exists() && bin2.canExecute() && bin2.length() > 0){
            debug_print("[checkBinary]:" + binaryName + " is now available.");
            return true;
        }

        debug_print("[checkBinary]: Failed to find/set " + binaryName + ".");
        return false;
    }

    /**
     * Returns the first IP occurence of the provided interface name.
     *
     * @param  interface_name String,      the display name of the interface you want an IP address of, e.g.: "rmnet1"
     * @return                InetAddress, contains the IP address on success, NULL on failure.
     */
    private InetAddress _getIP(String interface_name) {

        try {
            Enumeration<NetworkInterface> nis = NetworkInterface.getNetworkInterfaces();
            NetworkInterface ni;
            while (nis.hasMoreElements()) {
                ni = nis.nextElement();
                if (!ni.isLoopback() && ni.isUp()) {
                    for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                        if (ni.getDisplayName().equals(interface_name)) {
                            return ia.getAddress();
                        }
                    }
                }
            }
        } catch (Exception e) {
            debug_print("[_getIP]: " + e.getMessage());
        }
        return null;
    }


    /**
     * Gets the IPsec SA contents and displays them in the GUI
     */
    private void _getSaSecDetails(int sa_count) {
        if(sa_count != 4){
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    _txtSaProto.setText(" ");
                    _txtSaMode.setText(" ");
                    _txtSaEncrCipher.setText(" ");
                    _txtSaEncrKey.setText(" ");
                    _txtSaAuthKey.setText(" ");
                    _txtSaAuthCipher.setText(" ");
                }
            });
            debug_print("[getSaSecDetails]: text gui cleared.");
            return;
        }

        // Create a IPSec State Manager
        IPsecStateManager ism = new IPsecStateManager();

        // Get & parse 'ip x s'
        String getIPsecState = "stateofemergency";
        if(useLocalPcap.equals("true")){
            getIPsecState += "_debug";
        }
        List<String> ipsecState = StrategicCommand.secretIntelligence(getIPsecState);
        ism.updateSAState(ipsecState, sa_count);

        // Get & parse 'ip x p'
        List<String> ipsecPolicy = StrategicCommand.secretIntelligence("sipPorts");
        ism.updateSAPolicy(ipsecPolicy, sa_count);

        // Get SA and display in GUI.
        // The first SA is usually enough, same keys/ciphers
        _sa[0] = ism.getSA(0);
        _sa[1] = ism.getSA(1);
        _sa[2] = ism.getSA(2);
        _sa[3] = ism.getSA(3);

        debug_print("[getSaSecDetails] 0: " + _sa[0].toString());
        debug_print("[getSaSecDetails] 1: " + _sa[1].toString());
        debug_print("[getSaSecDetails] 2: " + _sa[2].toString());
        debug_print("[getSaSecDetails] 3: " + _sa[3].toString());

        // Asuming all four SA contain similair details:
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if(_sa[0] != null) {
                    _txtSaProto.setText(_sa[0].protocol);
                    _txtSaMode.setText(_sa[0].mode.toString());
                    _txtSaAuthCipher.setText(_sa[0].authAlgorithm.toString());
                    _txtSaEncrCipher.setText(_sa[0].encryptionAlgorithm.toString());

                    if (_sa[0].encryptionKey == null) {
                        _txtSaEncrKey.setText("0x");
                    } else {
                        _txtSaEncrKey.setText(_sa[0].encryptionKey);
                    }

                    if (_sa[0].authKey == null) {
                        _txtSaAuthKey.setText("0x");
                    } else {
                        _txtSaAuthKey.setText(_sa[0].authKey);
                    }
                } else {
                    _txtSaProto.setText(" ");
                    _txtSaMode.setText(" ");
                    _txtSaEncrCipher.setText(" ");
                    _txtSaEncrKey.setText(" ");
                    _txtSaAuthKey.setText(" ");
                    _txtSaAuthCipher.setText(" ");
                }
            }
        });
    }

    /**
     * Executes the runOnUiThread() to inmediatly updateSAState a button in the GUI of Android.
     * Method must be called within a new Thread() in order to work.
     *
     * @param btn        Button  The reference to the button to update
     * @param text       String  New text for inside the button, leave empty string for no updateSAState
     * @param clickable  Boolean TRUE for clickable, FALSE to disable the clickable event
     * @param bgcolor    int     Reference to a predefined color, e.g.: R.color.colorPrimary
     * @param visibility int     0 = visible (default), 4 = invisible, 8 = gone
     * @param sleep      int     Time in miliseconds to wait before executing the GUI updateSAState
     */
    private void _updateGuiBtn(final Button btn,
                               final String text,
                               final Boolean clickable,
                               final int bgcolor,
                               final int visibility,
                               final int sleep) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                try {
                    // Sleep before executing the gui updateSAState
                    Thread.sleep(sleep);

                    // Update text
                    if(!text.isEmpty())
                        btn.setText(text);

                    // Update clickable
                    btn.setClickable(clickable);

                    // Visibility, e.g.: View.VISIBLE
                    if(visibility == 0 || visibility == 4 || visibility == 8) {
                        btn.setVisibility(visibility);
                    } else {
                        btn.setVisibility(View.VISIBLE);
                    }

                    // Update background color
                    if(bgcolor != 0)
                        btn.setBackgroundColor(getResources().getColor(bgcolor, getTheme()));

                } catch (InterruptedException e) {
                    debug_print("[_updateGuiBtn] " + e.getMessage());
                }
            }
        });
    }

    /**
     * Wrapper to print debug text if debugging constant is enabled
     *
     * @param debug String the text to print at run-time
     */
    private void debug_print(String debug){
        if(_DEBUG)
            System.out.println(debug);
    }

    /**
     * Gets the amount of Security Associations (SA) of IPSec,
     * configured by the IP Transform framework (xfrm)
     *
     * @return Integer, The amount of SA available (should be 4)
     */
    private int _getSaCount() {
        int sa_count = 0;

        // Interrogate StratCom
        List<String> ipsecCount = StrategicCommand.secretIntelligence("frameofmind");

        // Get SA value from string
        if(useLocalPcap.equals("true")){
            sa_count = sa_count_pcap;
        } else {
            try {
                String[] ipsecCS = ipsecCount.get(0).split(" ");
                sa_count = Integer.valueOf(ipsecCS[ipsecCS.length - 1]);
            } catch (Exception e) {
                debug_print("[_getSaCount] " + e.getMessage());
            }
        }

        // Update the text view with SA value
        final int finalSa_count = sa_count;
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                // Display the SA count
                _txtSaCount.setText(String.valueOf(finalSa_count));

                // Give SA_count a color for good or bad
                if(finalSa_count == 4) {
                    _txtSaCount.setTextColor(Color.GREEN);
                } else {
                    _txtSaCount.setTextColor(Color.RED);
                }
            }
        });

        return sa_count;
    }

    /**
     * NOTE! Can only be called from the main thread!
     * Shows a short on-screen alert/message
     *
     * @param message String the message to display in the short popup in the bottom of the GUI
     */
    private void toastMessage(String message) {
        Toast.makeText(getApplicationContext(), message, Toast.LENGTH_LONG).show();
    }


    @Override
    public void onBackPressed() {
//        DrawerLayout drawer = (DrawerLayout) findViewById(R.id.drawer_layout);
//        if (drawer.isDrawerOpen(GravityCompat.START)) {
//            drawer.closeDrawer(GravityCompat.START);
//        } else {
//            super.onBackPressed();
//        }
        moveTaskToBack(true);
    }

    @Override
    protected void onResume() {
        _enableAirplaneModeDetection();
        super.onResume();
    }

    @Override
    protected void onPause() {
        debug_print("[onPause]");

        if(_brAirplane != null && receiversRegistered) {
            unregisterReceiver(_brAirplane);
            receiversRegistered = false;
        }

        super.onPause();
    }

    @Override
    protected void onDestroy() {
        stopBackgroundService();


        try {
            if(receiversRegistered)
                unregisterReceiver(_brAirplane);
        } catch (Exception e) {
            debug_print("[onDestroy]: Could not unregister the airplane mode BroadcastReceiver, " +
                    "airplane mode was probably not called, thus this can be ignored.");
        }

        // Only unregister our receiver when app gets killed.
        LocalBroadcastManager.getInstance(this).unregisterReceiver(ir);

        super.onDestroy();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @SuppressWarnings("StatementWithEmptyBody")
    @Override
    public boolean onNavigationItemSelected(MenuItem item) {
        // Handle navigation view item clicks here.
        int id = item.getItemId();

        if (id == R.id.nav_camera) {
            // Handle the camera action
        } else if (id == R.id.nav_gallery) {

        } else if (id == R.id.nav_slideshow) {

        } else if (id == R.id.nav_manage) {

        } else if (id == R.id.nav_share) {

        } else if (id == R.id.nav_send) {

        }

        DrawerLayout drawer = findViewById(R.id.drawer_layout);
        drawer.closeDrawer(GravityCompat.START);
        return true;
    }

    /**
     * Registers a recevier to detect changes in Airplane mode.
     * Initiates the verify function automatically if the user has pressed the button at least once before.
     */
    private void _enableAirplaneModeDetection() {

        // No need to redeclare/reregister the same receiver if it already exists.
        if(_brAirplane != null)
            return;

        _ifAirplane = new IntentFilter("android.intent.action.AIRPLANE_MODE");
        _brAirplane = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent)
            {
                // Get Airplane mode state
                _isAirplaneModeOn = isAirplaneModeOn(getApplicationContext());

                new Thread() {
                    public void run() {

                        if(state == States.VERIFY) {
                            debug_print("[AirplaneDetectionMode]: VERIFY");
                            if(!_isThreadRunning && _userHasStarted)
                            {
                                // Provide feedback
                                _updateGuiBtn(_btnVerify,"Network change detected...",false, R.color.colorWarning, View.VISIBLE,100);
                                _updateGuiBtn(_btnCaptureStart,"",false, 0, View.INVISIBLE, 0);

                                // Short sleep to let airplane mode do its thing.
                                try { Thread.sleep(2500); }
                                catch (Exception e) { debug_print("[_enableAirplaneModeDetection]: " + e.toString()); }

                                // Simulate auto onclick btn
                                onclickBtnVolteCompat(null);
                            }
                        } else if (state == States.CAPTURE) {
                            if(_isAirplaneModeOn) {
                                stopBackgroundService();
                                _isThreadRunning = false;
                                _updateGuiBtn(_btnCaptureStart, "Check Airplaine mode", false, R.color.colorWarning, View.VISIBLE, 10);
                            } else {
                                _updateGuiBtn(_btnCaptureStart, "start capture?", true, R.color.colorWarning, View.VISIBLE, 500);
                            }

                        }
                    }
                }.start();
            }
        };
        registerReceiver(_brAirplane, _ifAirplane);
    }

    /**
     * Returns the state of airplane mode.
     *
     * @param context The application context
     * @return TRUE if airplane mode is on, false if airplane mode is off.
     */
    private static boolean isAirplaneModeOn(Context context)
    {
        return Settings.Global.getInt(context.getContentResolver(), Settings.Global.AIRPLANE_MODE_ON, 0) != 0;
    }

    private static final int REQUEST_WRITE_STORAGE = 112;

    /**
     * Creates the directory 'sipwatcher' on the SDcard is it doesn't already exists.
     * @return
     */
    private boolean mkdirOnSD(){
        boolean hasPermission = (ContextCompat.checkSelfPermission(this,
                Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED);
        if (!hasPermission) {
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, REQUEST_WRITE_STORAGE);
        }
        return true;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode)
        {
            case REQUEST_WRITE_STORAGE: {
                if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED)
                {
                    try {
                        String folder_main = "sipwatcher";
                        File f = new File(Environment.getExternalStorageDirectory(), folder_main);
                        debug_print("[mkdirOnSD]: creating directory: " + Environment.getExternalStorageDirectory());

                        if (!f.exists()) {
                            if(f.mkdirs()){
                                debug_print("[mkdirOnSD]: directory created");
                            } else {
                                debug_print("[mkdirOnSD]: failed to create directory");
                            }
                        } else {
                            debug_print("[mkdirOnSD]: directory already existed");
                        }
                    } catch (Exception e) {
                        debug_print("[mkdirOnSD]: failed to create directory on sdcard: " + e.getMessage());
                    }
                }
                else
                {
                    Toast.makeText(this, "The app was not allowed to write to your storage. Hence, it cannot function properly. Please consider granting it this permission", Toast.LENGTH_LONG).show();
                }
            }
        }

    }


    /**
     * An inner class for MainActivity
     *
     * Defines the callback for what to do when data is received from our background service
     * Made static such that it can be defined in the AndroidManifest
     */
    public final static class IntelligenceReceiver extends BroadcastReceiver {

        @Override
        public void onReceive(Context context, Intent intent)
        {
            if (intent.getIntExtra("resultCode", RESULT_CANCELED) == RESULT_OK)
            {
                String            header   = intent.getStringExtra("header");
                ArrayList<String> contents = intent.getStringArrayListExtra("sipContents");

                // null check
                if(header == null || contents == null)
                    return;

                // empty check
                if(header.isEmpty() || contents.size() == 1)
                    return;

                System.out.println("[IntelligenceReceiver] broadcast received, adding to list...");
                _listDataHeader.add(header);
                _listDataChild.put(_listDataHeader.get(_brifCounter), contents);
                _brifCounter++;

                // Refresh GUI with the newly received data.
                UIHandler.post(new Runnable() {
                    @Override
                    public void run() {
                        _listAdapter.notifyDataSetChanged();
                    }
                });

            } else {
                System.out.println("[IntelligenceReceiver] resultCode error.");
            }
        }
    }
}