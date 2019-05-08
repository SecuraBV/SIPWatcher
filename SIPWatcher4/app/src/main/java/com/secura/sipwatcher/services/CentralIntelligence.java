package com.secura.sipwatcher.services;

import android.app.Activity;
import android.app.IntentService;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.support.annotation.Nullable;
import android.support.v4.content.LocalBroadcastManager;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;


// TODO http://android-er.blogspot.com/2013/03/generate-notification-in-intentservice.html ?
// create above notification service?
// Run this in a AVD? Android Virtual Device, -> https://stackoverflow.com/questions/5095234/how-to-get-root-access-on-android-emulator
//
// https://github.com/0xFireball/root_avd
// When downloading a 'System Image' during the AVD setup, select e.g. API level 24 and a NON 'Google APIs'!
//   else 'adb remount' wont work to get root/su permissions).
//

public class CentralIntelligence extends IntentService {

    // Identifiers for sending messages between this service and MainActivity
    public static final String ACTION        = "com.secura.sipwatcher.services.CentralIntelligence";
    public static final String ACTION_UDPATE = "com.secura.sipwatcher.services.CIUpdate";

    // Keep track of its running state.
    private boolean _isThreadRunning = false;

    // Volatile entails vars stored in 'main memory', and not cached thread-locally.
    // Thus these vars are shared between all threads, take caution though, e.g. atomic operations, race condition etc.;
    private volatile boolean _enableTsharkBufferFiller = false;
    private volatile AtomicInteger _sipSendCounter;
    private volatile AtomicInteger _tsharkFillerFilled;

    // IF and BR to receive messages from MainActivity during this service's lifetime.
    private IntentFilter      _ifCIUpdate = null;
    private BroadcastReceiver _brCIUpdate = null;


    private static  boolean debug             = true;
    private         String  localPcapLocation = "/sdcard/<YOUR_PCAP>.pcap";


    /**
     * Wrapper to print debug text if debugging constant is enabled
     * @param text String the text to print at run-time
     */
    private static void debug_print(String text){
        if(debug)
            System.out.println(text);
    }

    // Default constructor
    public CentralIntelligence() {
        super("CentralIntelligence");
    }

    @Override
    public void onCreate() {
        super.onCreate();
        // If a Context object is needed, call getApplicationContext() here.

        // Listen to incoming messages, e.g. from our main activity.
        listenForIncomingUpdates();

        _sipSendCounter = new AtomicInteger(0);
        _tsharkFillerFilled = new AtomicInteger(0);
    }

    /**
     * Creates and registers a broadcastReceiver to receive messages (intents)
     * Creates an IntentFilter receive only specific messages.
     * This function is used to stop the onHandleIntent() function, and ultimatly the whole service.
     */
    private void listenForIncomingUpdates() {
        // Listen for messages from our main activity to adjust this background service.
        _ifCIUpdate = new IntentFilter(ACTION_UDPATE);
        _brCIUpdate = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {

                // Update 1
                String setRunningState = intent.getStringExtra("setRunningState");
                if(setRunningState != null && setRunningState.equals("false")) {
                    debug_print("[CIBService]: intent received to stop capturing..");
                    _isThreadRunning = false;
                }

                // Update 2
                // ...
            }
        };
        registerReceiver(_brCIUpdate, _ifCIUpdate);
    }

    @Override
    public void onDestroy() {
        unregisterReceiver(_brCIUpdate);
        debug_print("[CIBService]: onDestroy: service is getting destroyed...");
        super.onDestroy();
    }

    @Override
    public void onLowMemory() {
        debug_print("[CIBService]: service is getting low on memory...");
        super.onLowMemory();
    }

    @Override
    protected void onHandleIntent(@Nullable Intent intent) {
        // This describes what will happen when service is triggered
        debug_print("[CIBService]: service starting...");

        // Make sure we receive an intent, else null pointer exception.
        if(intent == null){
            debug_print("[CIBService]: error: intent is empty.");
            return;
        }

        // Our map which holds the key/value of how the capture should run/decode
        Map<String, String> req = new HashMap<>();

        // Assuming all params are Strings
        // A list of required params in order to run:
        String[] requiredArgsFromMainActivity = {"tsharkLoc", "tcpdumpLoc",                         // Binary file location
                                                 "encrKey",   "authKey",
                                                 "encrAlgo",  "authAlgo",
                                                 "sport0",    "sport1",     "sport2", "sport3",     // SIP source ports
                                                 "ipVersion",                                       // IPv 4 or 6
                                                 "envp",                                            // Library environment
                                                 "packetSeperator",
                                                 "useLocalPcap",                                    // Test mode y/n
                                                 "ipSrc"};                                          // The IP of the device

        // Loop through the required arguments, null check & store them in our HashMap
        for(String arg : requiredArgsFromMainActivity){
            // Get the value
            String argValue = intent.getStringExtra(arg);

            // Assert null & store
            if(argValue != null) {
                req.put(arg, argValue);
            } else {
                debug_print("[CIBService]: error: missing argument: " + arg);
                return;
            }
        }

        // Thread running condition
        if(_isThreadRunning){
            debug_print("[CIBService]: service was already running, stopping...");
            _isThreadRunning = false;
            return;
        } else {
            debug_print("[CIBService]: service was not yet running, continuing...");
            _isThreadRunning = true;
        }

        // Checks if we need to call our own tcpdump or can use a system wide tcpdump
        String tcpdump = ((req.get("tcpdumpLoc").startsWith(this.getFilesDir().getPath()))
                            ? "." + req.get("tcpdumpLoc")
                            : req.get("tcpdumpLoc"));

        // Add tcpdump parameters
        tcpdump += " 'esp "
                +  "or port 53 "                                // dns
                +  "or port 5060 "                              // sip
                +  "or port " + req.get("sport0") + " "         // ipsec sa
                +  "or port " + req.get("sport1") + " "         // ipsec sa
                +  "or port " + req.get("sport2") + " "         // ipsec sa
                +  "or port " + req.get("sport3") + "' "        // ipsec sa
                +  "-i any -s 0 -U -w -";

        // Determine which input to use for tshark
        String tsharkReadInput = " -r " + ((req.get("useLocalPcap").equals("true"))
                    ? localPcapLocation   // read our local pcap file
                    : "-");                     // read stdin

        // Add tshark including its parameters
        // Don't add tshark display filter '-Y sip' due an issue with tshark 2.4.x
        String tshark = "./data/user/0/com.secura.sipwatcher/files/arm-linux-androideabi-tshark" +
                " -O raw_sip" +                                          // protocol filter, only show raw sip of each message
                " -o 'uat:esp_sa:" +                                     // SA details to decode SIP, inline instead of SA file
                "\""+req.get("ipVersion")+"\"," +                        // IP version
                "\"*\"," +                                               // IP source      (* = all)
                "\"*\"," +                                               // IP destination (* = all)
                "\"*\"," +                                               // SA SPI         (* = all)
                "\""+req.get("encrAlgo")+"\"," +                         // Encryption algorithm
                "\""+req.get("encrKey")+"\"," +                          // Encryption key
                "\""+req.get("authAlgo")+"\"," +                         // Authentication algorithm
                "\""+req.get("authKey")+"\"'" +                          // Authentication key
                " -o esp.enable_encryption_decode:TRUE" +                // decrypt SIP
                " -o sip.display_raw_text:TRUE" +                        // shorter SIP
                " -o sip.display_raw_text_without_crlf:TRUE" +           // Removes \r\n after each raw sip line
                " -d tcp.port=="+req.get("sport0")+",sip" +              // Decode as SIP
                " -d tcp.port=="+req.get("sport1")+",sip" +              // Decode as SIP
                " -d tcp.port=="+req.get("sport2")+",sip" +              // Decode as SIP
                " -d tcp.port=="+req.get("sport3")+",sip" +              // Decode as SIP
                " -S \""+req.get("packetSeperator")+"\"" +               // Packet seperator
                " -P " +                                                 // Packet summary
                " -l " +                                                 // flush standard output after each packet
                tsharkReadInput +                                        // read input
                "";

        // Create an esp_sa file used by wireshark to decode esp traffic.
        // Such that users can extract the created pcap and use this file to decode the traffic
        String esp_sa_file = " echo '# This file is automatically generated, DO NOT MODIFY." +
                "\n" +
                "\""+req.get("ipVersion")+"\"," +
                "\"*\"," +
                "\"*\"," +
                "\"*\"," +
                "\""+req.get("encrAlgo")+"\"," +
                "\""+req.get("encrKey")+"\"," +
                "\""+req.get("authAlgo")+"\"," +
                "\""+req.get("authKey")+"\"'" +
                " > /sdcard/sipwatcher/$(date +%Y-%m-%d_%H.%M.%S)_esp_sa";

        // Chain all the commands together.
        final String cmd = esp_sa_file
                + " ; "
                + tcpdump
                + " | "
                + "tee /sdcard/sipwatcher/$(date +%Y-%m-%d_%H.%M.%S)_capture.pcap" // Save tcpdump to file
                + " | "
                + tshark;

        // Fill tshark output buffer when needed.
        startThreadToFillTsharkBuffer();

        // The meat of the service
        try {
            Process        process = Runtime.getRuntime().exec("su"); // Request SU permissions
            OutputStream   stdin   = process.getOutputStream();
            InputStream    stderr  = process.getErrorStream();
            InputStream    stdout  = process.getInputStream();
            String         line;
            BufferedReader br;

            // We require to set this environment such that tshark can find its libraries.
            stdin.write((req.get("envp") + "\n").getBytes());

            // Execute tshark
            stdin.write((cmd + "\n").getBytes());
            stdin.flush();

            // Get output
            br = new BufferedReader(new InputStreamReader(stdout));
            try {
                boolean      lineIsPacketSummary   = true;      // first line of every packet is a summary (hence -P of tshark)
                boolean      skipMessage           = false;
                String       header                = "";        // clear & define header.
                List<String> sipContents           = new ArrayList<>();

                // Lets run!
                while (_isThreadRunning) {

                    // line available? (to prevent blocking state)
                    if(br.ready()){
                        if((line = br.readLine()) != null){

                            // Filter out some unwanted traffic, but essential to receive to fill tsharks output buffer.
                            if(skipMessage && line.equals(req.get("packetSeperator"))) {
                                skipMessage = false;
                                continue;
                            } else if(skipMessage) {
                                continue;
                            }

                            // Parse the first (summary) line of a packet
                            if(lineIsPacketSummary){

                                // We dont need tcpdump's initial output
                                if(line.startsWith("tcpdump: listening on") || line.startsWith("resetting session"))
                                    continue;

                                // Skip whole message if the summary line does say it is SIP message
                                if(!line.contains(" SIP")){
                                    skipMessage = true;
                                    continue;
                                }

                                // Make sure to stop our tshark buffer filler at this point.
                                _enableTsharkBufferFiller = false;

                                // Trim whitespace and explode into a HashMap for easier parsing
                                String[] tmp = line.trim().split(" ");
                                Map<String, String> summary = new HashMap<>();
                                int lastMessage = 0;

                                // Extract values
                                for(int k = 0; k < tmp.length; k++){
                                    if(tmp[k].equals("→")){
                                        summary.put("src", tmp[k-1]);
                                        summary.put("dst", tmp[k+1]);
                                        summary.put("sip", tmp[k+2]);
                                    }
                                    if(tmp[k].equals("Status:")){
                                        summary.put("transaction", tmp[k]);
                                        summary.put("message", tmp[k+1] + " " + tmp[k+2]);
                                        lastMessage = k+2;
                                    }
                                    else if(tmp[k].equals("Request:")){
                                        summary.put("transaction", tmp[k]);
                                        summary.put("message", tmp[k+1]);
                                        lastMessage = k+1;
                                    }
                                    if(k > lastMessage){
                                        if(!tmp[k].equals("|") && !tmp[k].contains("sip:"))
                                            summary.put("message", summary.get("message") + " " + tmp[k]);
                                    }
                                }

                                // Construct our desired header
                                header  = summary.get("sip")         + " "
                                        + summary.get("transaction") + " "
                                        + summary.get("message");

                                // Compare the IP src of the message to our device
                                // to determine the direction of the message
                                if(summary.get("src") != null && summary.get("dst") != null){
                                    header = ((summary.get("src").equals(req.get("ipSrc")))
                                            ? "↑ " + header         // Source is our own device, so outgoing message
                                            : header + " ↓");       // Source is SIP proxy, so incoming message.
                                }

                                lineIsPacketSummary = false;
                                continue;
                            }

                            // When all packet lines are received/complete:
                            if(line.equals(req.get("packetSeperator"))){

                                // Construct an Intent tied to the ACTION name
                                Intent in = new Intent(ACTION);

                                // To send a message to the Activity, create a pass a Bundle
                                in.putExtra("resultCode", Activity.RESULT_OK);
                                in.putExtra("header",     header);
                                in.putStringArrayListExtra("sipContents", (ArrayList<String>) sipContents);

                                // Fire the broadcast with intent packaged
                                LocalBroadcastManager.getInstance(this).sendBroadcastSync(in);

                                debug_print("[CIBService]: SEND ("+header+") to MAIN.");

                                // Ready vars for next SIP message
                                sipContents = new ArrayList<>();

                                // next interation
                                _tsharkFillerFilled.set(0);
                                _sipSendCounter.getAndIncrement();
                                lineIsPacketSummary = true;
                                _enableTsharkBufferFiller = true;
                                stdin.flush();
                                continue;
                            }

                            // Exclude uninteresting lines
                            if(line.isEmpty()
                                    || line.contains("Linux cooked capture")
                                    || line.equals("      ")
                                    || line.contains("Session Initiation Protocol (SIP as raw text)")
                                    || line.startsWith("Frame")
                                    || line.contains("Reassembled TCP Segments"))
                                continue;

                            // Remove "[truncated]"
                            line = line.replace("[truncated]", "");

                            // Add line to collection
                            sipContents.add(line);

                        }
                    } else {

                        // If arrived here, then BufferedReader was not yet ready
                        // So wait a bit... saves cpu/battery?
                        Thread.sleep(1000);
                        debug_print("[CIBService]: running...");

                    }
                } // while

                debug_print("[CIBService]: Capture stopped, stopping service...");

            } catch (Exception e) {
                debug_print("[CIBService]: Service crashed #1: " + e.getMessage());
            }

            debug_print("[CIBService]: Stopping service...");
            stdin.write("exit\n".getBytes());
            stdin.flush();
            stdin.close();

            // Error assessment
            br = new BufferedReader(new InputStreamReader(stderr));
            /*while ((*/line = br.readLine();//) != null) {         // its enough to read one line, else it might block
                debug_print("[CIBService] stderr: " + line);
            //}

            // close resources
            br.close();
            process.destroy();

        } catch (Exception e) {
            debug_print("[CIBService]: Service crashed #2: " + e.getMessage());
            e.getStackTrace();
        }

        debug_print("[CIBService]: Service stopped.");
    }

    /**
     * Please note the following:
     *
     * The use of tshark 2.4.x implies an issue as described below:
     *          Re: tshark buffered packet dissection -- no realtime output?
     *          http://seclists.org/wireshark/2018/Jan/109
     * The issue is: tshark buffers its output to 4k bytes before sending it through (even with -l param)
     * Cross-compiling wireshark/tshark 2.6 failed due unsovlable issues
     * To work around this issue, we force fill tsharks buffer with self-crafted packets.
     * As such, we send a series of DNS requests in order to receive all our SIP message.
     * Definitely not an elegant solution, and very hacky, but it works.
     * A slight improvement would be to set the DNS requests TTL to 1.
     */
    private void startThreadToFillTsharkBuffer() {
        new Thread() {
            public void run() {

                // Only run if capture thread is running.
                while(_isThreadRunning) {

                    // Wait at least one second.
                    try { Thread.sleep(1000); }
                    catch (InterruptedException e) { }

                    // If there where SIP messages send, and our DNS boolean is set, then go
                    if(_sipSendCounter.get() > 0 && _enableTsharkBufferFiller) {

                        // Inform the start of DNS filling
                        debug_print("[CIBService DNS]: starting...");

                        // Limit the amount of DNS requests send, we don't want this to be infinite.
                        while(_enableTsharkBufferFiller && _tsharkFillerFilled.get() < 1000 && _sipSendCounter.get() > 0) {
                            try {
                                Thread.sleep(50);
                                _tsharkFillerFilled.getAndAdd(sendDnsRequest());
                            } catch (Exception e) { }
                        }

                        // Change our sipcounter to reduce or stop this while
                        if(_tsharkFillerFilled.get() < 1000) {
                            _sipSendCounter.getAndDecrement();
                        } else {
                            _sipSendCounter.set(0);
                        }

                        debug_print("[CIBService DNS]: " + _tsharkFillerFilled + " bytes filled, reset!");
                        _tsharkFillerFilled.set(0);
                    }
                }
            }
        }.start();
    }

    /**
     * Please read JavaDoc of startThreadToFillTsharkBuffer() for why this function is included.
     * Sends and receives a DNS messages which requests the location of google.com at 8.8.8.8 (Googles DNS server)
     *
     * @return The amount of bytes sent.
     */
    private int sendDnsRequest() throws Exception {
        String DNS_SERVER_ADDRESS  = "8.8.8.8";
        int DNS_SERVER_PORT        = 53;
        String domain              = "google.com";
        InetAddress ipAddress      = InetAddress.getByName(DNS_SERVER_ADDRESS);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos       = new DataOutputStream(baos);

        int packetsize = 0;

        dos.writeShort(0x1234);
        dos.writeShort(0x0100);
        dos.writeShort(0x0001);
        dos.writeShort(0x0000);
        dos.writeShort(0x0000);
        dos.writeShort(0x0000);

        String[] domainParts = domain.split("\\.");

        for (int i = 0; i<domainParts.length; i++) {
            byte[] domainBytes = domainParts[i].getBytes("UTF-8");
            dos.writeByte(domainBytes.length);
            dos.write(domainBytes);
        }

        dos.writeByte(0x00);
        dos.writeShort(0x0001);
        dos.writeShort(0x0001);

        byte[] dnsFrame = baos.toByteArray();

        // *** Send DNS Request Frame ***
        DatagramSocket socket = new DatagramSocket();
        DatagramPacket dnsReqPacket = new DatagramPacket(dnsFrame, dnsFrame.length, ipAddress, DNS_SERVER_PORT);

        packetsize = dnsReqPacket.getLength();
        socket.send(dnsReqPacket);

        // Await response from DNS server
        byte[] buf = new byte[1024];
        DatagramPacket packet = new DatagramPacket(buf, buf.length);
        socket.receive(packet);

        return packetsize;

    }
}

