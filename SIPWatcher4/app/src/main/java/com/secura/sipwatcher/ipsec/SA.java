package com.secura.sipwatcher.ipsec;

public class SA {
    public String strSrcIP, strDstIP, spi, protocol, authKey, encryptionKey, sport, dport;
    public int    requestId, replay_window;
    public Mode   mode;
    public AAlgo  authAlgorithm;
    public EAlgo  encryptionAlgorithm;

    // Default constructor
    public SA() { }

    // List of algorithms
    public enum AAlgo {NULL, HMAC_SHA1_96, HMAC_MD5_96}
    public enum EAlgo {NULL, AES_CBC, TRIPPLE_DES_CBC}

    @Override
    public String toString() {
        return "SA{" +
                "src=" + strSrcIP +
                ", dst=" + strDstIP +
                ", sport=" + sport +
                ", dport=" + dport +
                ", protocol='" + protocol + '\'' +
                ", spi=" + spi +
                ", requestId=" + requestId +
                ", mode=" + mode +
                ", replay_window=" + replay_window +
                ", authAlgorithm=" + authAlgorithm +
                ", authKey=" + authKey +
                ", encryptionAlgorithm=" + encryptionAlgorithm +
                ", encryptionKey=" + encryptionKey +
                '}';
    }

    public enum Mode {
        TRANSPORT, TUNNEL;

        public static Mode fromAlias(String alias) {
            if (alias.equalsIgnoreCase("transport")) {
                return TRANSPORT;
            } else if (alias.equalsIgnoreCase("tunnel")) {
                return TUNNEL;
            }
            return null;
        }
    }

    public static AAlgo toAuthAlgo(String alias) {
        if (alias.equalsIgnoreCase("hmac(md5)")) {
            return AAlgo.HMAC_MD5_96;
        } else if (alias.equalsIgnoreCase("hmac(sha1)")) {
            return AAlgo.HMAC_SHA1_96;
        } else if (alias.contains("null")) {
            return AAlgo.NULL;
        }
        return null;
    }

    public static EAlgo toEncryptionAlgo(String alias) {
        if (alias.equalsIgnoreCase("cbc(aes)")) {
            return EAlgo.AES_CBC;
        } else if (alias.equalsIgnoreCase("cbc(des3_ede)")) {
            return EAlgo.TRIPPLE_DES_CBC;
        } else if (alias.contains("null")) {
            return EAlgo.NULL;
        }
        return null;
    }
}

