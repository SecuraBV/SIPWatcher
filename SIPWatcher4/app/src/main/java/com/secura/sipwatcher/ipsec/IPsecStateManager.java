package com.secura.sipwatcher.ipsec;

import java.util.List;

/**
 * Class is based on the IPsecDecryptor project created by created by Zhang Jie on Aug 7 2014.
 * https://github.com/adenzhang/IPsecDecryptor
 */
public class IPsecStateManager {
    private SA[] _sa_array;

    public IPsecStateManager() {
        _sa_array = new SA[4];
    }

    /**
     * Requests one of four Security Associations
     *
     * @param  index Which SA of the four, {0, 1, 2, 3}
     * @return       The SA object containing its security details.
     */
    public SA getSA(int index){
        if(index >= 0 && index <= 3){
            try {
                return _sa_array[index];
            } catch(IndexOutOfBoundsException e) {
                System.out.println("[getSA] Index out of bounds: " + e.getMessage());
            }
        }
        return null;
    }

    /**
     * Update the SA state with the information from the cmd: ip xfrm state (ip x s)
     *
     * @param lines    A list of lines of the ip x s output
     * @param sa_count The amount of SA available, should be 4
     */
    public void updateSAState(List<String> lines, int sa_count) {

        if(sa_count != 4)
            return;

        int i = 0;
        SA sa = new SA();

        for(String s:lines) {
            String line = s.trim();
            if (line != null && line.length() != 0) {
                String[] tokens = line.split(" ");
                for (int index = 0; index < tokens.length; ) {
                    index = parseParameter(sa, tokens, index) + 1;
                }
                if (line.startsWith("sel")) {  // last line of an SA record
                    _sa_array[i] = sa;
                    i++;
                    sa = new SA();
                }
            }
        }
    }

    /**
     * Update the SA state with the information from the cmd: ip xfrm state (ip x s)
     *
     * @param lines    A list of lines of the ip x s output
     * @param sa_count The amount of SA available, should be 4
     */
    public void updateSAPolicy(List<String> lines, int sa_count) {

        if(sa_count != 4)
            return;

        int i = 0;
        SA sa = _sa_array[i];

        for(String s:lines) {
            String line = s.trim();
            if (line != null && line.length() != 0) {
                String[] tokens = line.split(" ");
                for (int index = 0; index < tokens.length; ) {
                    index = parseParameter(sa, tokens, index) + 1;
                }
                if (line.startsWith("proto")) {  // last line of an SA record
                    _sa_array[i] = sa;
                    if(i <= 2){
                        i++;
                        sa = _sa_array[i];
                    }

                }
            }
        }
    }


    private int parseParameter(SA sa, String[] tokens, int currentPosition) {
        if (tokens[currentPosition].equalsIgnoreCase("src")) {
            try {
                currentPosition++;
                sa.strSrcIP = tokens[currentPosition];
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else if (tokens[currentPosition].equalsIgnoreCase("dst")) {
            currentPosition++;
            sa.strDstIP = tokens[currentPosition];
        } else if (tokens[currentPosition].equalsIgnoreCase("proto")) {
            currentPosition++;
            sa.protocol = tokens[currentPosition];
        } else if (tokens[currentPosition].equalsIgnoreCase("sport")) {
            currentPosition++;
            sa.sport = tokens[currentPosition];
        } else if (tokens[currentPosition].equalsIgnoreCase("dport")) {
            currentPosition++;
            sa.dport = tokens[currentPosition];
        } else if (tokens[currentPosition].equalsIgnoreCase("spi")) {
            currentPosition++;
            sa.spi = tokens[currentPosition];
        } else if (tokens[currentPosition].equalsIgnoreCase("reqid")) {
            currentPosition++;
            sa.requestId = Integer.parseInt(tokens[currentPosition]);
        } else if (tokens[currentPosition].equalsIgnoreCase("mode")) {
            currentPosition++;
            sa.mode = SA.Mode.fromAlias(tokens[currentPosition]);
        } else if (tokens[currentPosition].equalsIgnoreCase("auth-trunc")) {
            currentPosition++;
            sa.authAlgorithm = SA.toAuthAlgo(tokens[currentPosition]);
            if (sa.authAlgorithm != SA.AAlgo.NULL) {
                currentPosition++;
                sa.authKey = tokens[currentPosition];
            }
        } else if (tokens[currentPosition].equalsIgnoreCase("enc")) {
            currentPosition++;
            sa.encryptionAlgorithm = SA.toEncryptionAlgo(tokens[currentPosition]);
            if (sa.encryptionAlgorithm != SA.EAlgo.NULL) {
                currentPosition++;
                sa.encryptionKey = tokens[currentPosition];
            }
        } else {
            currentPosition++;
        }
        return currentPosition;
    }

}
