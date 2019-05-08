package com.secura.sipwatcher;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.LinkedList;
import java.util.List;

/**
 * The StrategicCommand class is responsible for delivering all-source intelligence while enabling
 * the execution of assigned strategic deterrence, space and cyberspace operations.
 */
final public class StrategicCommand {

    /**
     * Wrapper to print debug text if debugging constant is enabled
     * @param text String the text to print at run-time
     */
    private static void debug_print(String text){
        boolean debug = false;
        if(debug)
            System.out.println(text);
    }

    /**
     * Executes commands with user privileges and returns the outputs as a list of strings.
     *
     * @param  cmd The command to execute with Su privileges (whitelisted).
     * @return     A list of strings (per line) containing the output of the cmd.
     */
    protected static List<String> globalOperations(String cmd) {
        // Planning
        List<String> lines   = new LinkedList<>();
        String       line    = null;
        Process      process;

        // Communcation control
        if(cmd != null && !cmd.isEmpty()){
            switch(cmd) {
                case "bigbrother":
                    cmd = "which tcpdump";
                    break;
                case "skonarf":
                    cmd = "which tshark";
                    break;
                default:
                    // Strategic warning
                    debug_print("[globalOperations] unauthorized threat detected: " + cmd);
                    return lines;
            }
        }

        try {
            // Strike
            process = Runtime.getRuntime().exec(cmd);
            BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()));

            // Exfiltrate
            try {
                while ((line = br.readLine()) != null) {
                    lines.add(line);
                }
            } catch (Exception e){
                debug_print("[globalOperations] Error: " + line + " ** " + e.getMessage());
            }

            // Cover tracks
            br.close();
            process.waitFor();
            process.destroy();

        } catch (Exception e) {
            // Strategic warning
            debug_print("[_execCmd] Error: " + e.getMessage());
        }

        // Regroup
        return lines;
    }

    /**
     * Executes commands with SU privileges and returns the outpust as a list of strings.
     *
     * @param  cmd The command to execute with Su privileges (whitelisted).
     * @return     A list of strings (per line) containing the output of the cmd.
     */
    protected static List<String> secretIntelligence(String cmd) {
        // Planning
        List<String> lines = new LinkedList<>();
        String line        = null;
//        StringBuilder sb   = new StringBuilder();

        // Communcation control
        if(cmd != null && !cmd.isEmpty()){
            switch(cmd) {
                case "stateofemergency_debug":
                    // an easy way of adding the output of ip xfrm state into the application, when using a local pcap and a Android Virtual Device
                    // user specific details are omitted, might be a useful template for you, so i left this here.
                    lines.add("src 1234:123:1234::1 dst 1234:123:1234:1234:1:1:1234:1234");
                    lines.add("proto esp spi 0x00000001 reqid 13 mode transport");
                    lines.add("replay-window 4");
                    lines.add("auth-trunc hmac(md5) 0x12345678912345678912345678abcdef 96");
                    lines.add("enc ecb(cipher_null)");
                    lines.add("anti-replay context: seq 0x9, oseq 0x0, bitmap 0x000001ff");
                    lines.add("sel src ::/0 dst ::/0");
                    lines.add("src 1234:123:1234:1234:1:1:1234:1234 dst 1234:123:1234::1");
                    lines.add("proto esp spi 0x00000002 reqid 12 mode transport");
                    lines.add("replay-window 4");
                    lines.add("auth-trunc hmac(md5) 0x12345678912345678912345678abcdef 96");
                    lines.add("enc ecb(cipher_null)");
                    lines.add("anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000");
                    lines.add("sel src ::/0 dst ::/0");
                    lines.add("src 1234:123:1234::1 dst 1234:123:1234:1234:1:1:1234:1234");
                    lines.add("proto esp spi 0x00000003 reqid 11 mode transport");
                    lines.add("replay-window 4");
                    lines.add("auth-trunc hmac(md5) 0x12345678912345678912345678abcdef 96");
                    lines.add("enc ecb(cipher_null)");
                    lines.add("anti-replay context: seq 0x41, oseq 0x0, bitmap 0xffffffff");
                    lines.add("sel src ::/0 dst ::/0");
                    lines.add("src 1234:123:1234:1234:1:1:1234:1234 dst 1234:123:1234::1");
                    lines.add("proto esp spi 0x00000004 reqid 10 mode transport");
                    lines.add("replay-window 4");
                    lines.add("auth-trunc hmac(md5) 0x12345678912345678912345678abcdef 96");
                    lines.add("enc ecb(cipher_null)");
                    lines.add("anti-replay context: seq 0x0, oseq 0x4d, bitmap 0x00000000");
                    lines.add("sel src ::/0 dst ::/0");
                    return lines;
                case "stateofemergency":
                    cmd = "ip x s";
                    break;
                case "frameofmind":
                    cmd = "ip x s c";
                    break;
                case "facetheinn":
                    cmd = "ip a | grep rmnet1";
                    break;
                case "sipPorts":
                    cmd = "ip x p";
                    break;
                default:
                    // Strategic warning
                    debug_print("[secretIntelligence] unauthorized threat detected");
                    return lines;
            }
        }

        try {
            // Reconnaissance
            Process process    = Runtime.getRuntime().exec("su");
            OutputStream stdin = process.getOutputStream();
            InputStream stderr = process.getErrorStream();
            InputStream stdout = process.getInputStream();

            // Strike
            stdin.write((cmd + "\n").getBytes());
            stdin.write("exit\n".getBytes());

            // Escape
            stdin.flush();
            stdin.close();

            // Exfiltrate
            BufferedReader br = new BufferedReader(new InputStreamReader(stdout));
            try {
                while ((line = br.readLine()) != null) {
                    lines.add(line);
                }
            } catch (Exception e){
                // Strategic warning
                debug_print("[secretIntelligence] Error: " + line);
            }

            // Fade
            br.close();

            // Error assessment
            br = new BufferedReader(new InputStreamReader(stderr));
            while ((line = br.readLine()) != null) {
                debug_print("[secretIntelligence] Error: " + line);
            }

            // Cover tracks
            br.close();
            process.waitFor();
            process.destroy();

        } catch (Exception e) {
            // Strategic warning
            debug_print("[secretIntelligence] Error: " + e.getMessage());
        }

        // Regroup
        return lines;
    }

}
