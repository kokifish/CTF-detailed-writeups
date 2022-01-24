import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.*;
import java.net.URLEncoder;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Random;

public class YzddCrackme {
    byte[] input_temp;
    byte[] PBEWITHMD5andDES_bytes;
    String PBEWITHMD5andDES;
    public final String user_input;
    Key key;
    PBEParameterSpec params;
    Cipher cipher;

    YzddCrackme(String user_input) {
        this.PBEWITHMD5andDES_bytes = new byte[] { 80, 66, 69, 87, 73, 84, 72, 77, 68, 53, 97, 110, 100, 68, 69, 83 }; // PBEWITHMD5andDES
        this.PBEWITHMD5andDES = new String(this.PBEWITHMD5andDES_bytes);
        this.user_input = user_input;
    }

    public String buildToHex(byte[] usr_input) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < usr_input.length; ++i) {
            String tempStr = Integer.toHexString(usr_input[i] & 0xFF);
            if (tempStr.length() == 1) {
                builder.append("0" + tempStr);
            } else {
                builder.append(tempStr);
            }
            // System.out.printf("%x,%x; %s; %s\n", usr_input[i], usr_input[i] & 0xFF,
            // tempStr, builder.toString());
        }

        return builder.toString().toUpperCase();
    }

    // 16D71D14B3F9B6519A28AB54
    // 480E1C995149230BC5DF87EEB25E2F8A4B01B9F307391E35 ->
    public byte[] reverseToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) (((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16)));
            // System.out.printf("%x; %s; %s\n", data[i / 2], Character.digit(s.charAt(i),
            // 16), Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private Key generateSecret(String Google) { // 轮加密密钥
        Key key = null;
        if (Google != null && Google.length() != 0) {
            try {
                key = SecretKeyFactory.getInstance(this.PBEWITHMD5andDES)
                        .generateSecret(new PBEKeySpec(Google.toCharArray()));
            } catch (Exception v1) {
            }
        }
        PBEKeySpec PBEKeySpecValue = new PBEKeySpec(Google.toCharArray());
        // key.toString() com.sun.crypto.provider.PBEKey@4312482b 表示class全名？
        // key.getEncoded() to String: Google // getFormat: RAW
        // getAlgorithm: PBEWithMD5AndDES

        System.out.printf("[PBEKeySpec] %s, getEncoded:%s\n", new String(key.getAlgorithm()),
                Arrays.toString(key.getEncoded()));
        System.out.printf("[PBEKeySpec] PBEKeySpecValue: %s\n", new String(PBEKeySpecValue.getPassword()));
        System.out.println("key:" + key);
        return key;
    }

    private byte[] encrypt_core(String Google, byte[] user_input_2, byte[] AndroidN) { // 也许是加密过程的核心
        byte[] after_encrypt = null;
        key = this.generateSecret(Google); // 生成一个私钥

        if (key != null) {
            try {
                // byte[] salt, int iterationCount
                params = new PBEParameterSpec(AndroidN, 50);
                // params.getSalt: AndroidN params.getIterationCount: 50
                System.out.printf("[Para] %s, iter=%d\n", new String(params.getSalt()), params.getIterationCount());
                cipher = Cipher.getInstance(this.PBEWITHMD5andDES);
                // Note that this algorithm implies CBC as the cipher mode and PKCS5Padding as
                // the padding scheme and cannot be used with any other cipher modes or padding
                // schemes.
                // PKCS5 只能用來填充 8 Byte (64bit）的Block，除此之外可以混用
                // Cipher.ENCRYPT_MODE: 1
                cipher.init(1, key, ((AlgorithmParameterSpec) params));
                // cipher.getParameters();
                byte[] IV = cipher.getIV();
                System.out.printf("[cipher] IV: %s, alg:%s\n", Arrays.toString(cipher.getIV()), cipher.getAlgorithm());
                after_encrypt = cipher.doFinal(user_input_2);
            } catch (Exception exc) {
                System.out.println("Exception:" + exc);
            }
        }
        return after_encrypt;
    }

    private byte[] decrypt(byte[] input) throws BadPaddingException {
        byte[] after_encrypt = null;

        try {
            cipher.init(Cipher.DECRYPT_MODE, key, ((AlgorithmParameterSpec) params));
            after_encrypt = cipher.doFinal(input);
        } catch (Exception exc) {
            System.out.println("Exception:" + exc);
        }

        return after_encrypt;
    }

    public String JavaEncrypt(String input) throws UnsupportedEncodingException {
        input_temp = input.getBytes();
        input_temp = encrypt_core("Google", input_temp, "AndroidN".getBytes());
        String hexed = input_temp == null ? "" : buildToHex(input_temp);
        String finalStr = URLEncoder.encode(hexed, "UTF-8");
        return finalStr;
    }

    public byte[] JavaDecrypt(String input) throws UnsupportedEncodingException, BadPaddingException {
        String decoded = java.net.URLDecoder.decode(input, "UTF-8");
        byte[] re = reverseToBytes(decoded);
        byte[] decrypted = null;
        try {
            decrypted = decrypt(re);
        } catch (BadPaddingException e) {
            System.out.println("[JavaDecrypt] ERROR");
        }
        return decrypted;
    }

    public static void main(String[] args) throws IOException {
        YzddCrackme crack = new YzddCrackme("0000000000000000");
        System.out.printf("[original] %s, len=%d\n", crack.user_input, crack.user_input.length());

        String encrypted = crack.JavaEncrypt("0000000000000000");
        System.out.printf("[encrypt] %s, len=%d\n", encrypted, encrypted.length());
        byte[] decrypted = null;
        try {
            decrypted = crack.JavaDecrypt(encrypted);
        } catch (BadPaddingException e) {

        }

        System.out.printf("[Decrypt] %s, len=%d should be same as original\n", new String(decrypted), decrypted.length);
        ///////////////////////////////////////////////////////////////////////
        String lhs = "0CDB3008BCF48850A8A07877";// \000 表示\0
        System.out.printf("lhs:%s, len=%d\n", lhs, lhs.length());

        // NOTE: 对比字符串似乎无法decrypt, 但是strcmp会被\0截断，所以后面的可以不同，只要截断位置一样，且截断前相同，爆破？
        OutputStream outf = new FileOutputStream("D:\\java.txt");
        Random rd = new Random();
        String CharSet = "0123456789ABCDEF";
        int loop = 2;
        while (true) {
            String randStr = "";
            for (int i = 0; i < 8; i++) {
                randStr = CharSet.charAt(rd.nextInt(CharSet.length())) + randStr;
                // System.out.printf("randStr:%s, len=%d, i=%d\n", randStr, randStr.length(),
                // i);
            }

            String guess = lhs.concat(randStr);
            // System.out.printf("guess:%s, len=%d, substr: %s\n", guess, guess.length(),
            // guess.substring(16, 32));
            String[] arguments = new String[] { "python",
                    "D:\\OneDrive\\CTF-detailed-writeups\\android\\IDA_debug_yzdd_crackme\\DES.py",
                    guess.substring(16, 32) };
            String TheLastEncrypted8B = "";
            try {
                Process process = Runtime.getRuntime().exec(arguments);
                BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String tmp_last_block = null;
                while ((tmp_last_block = in.readLine()) != null) {
                    // System.out.println("tmp_last_block:" + tmp_last_block);
                    TheLastEncrypted8B = tmp_last_block;
                }
                in.close();
                int re = process.waitFor();
                // System.out.println("re:" + re);
            } catch (Exception e) {
                e.printStackTrace();
            }
            // System.out.println("TheLastEncrypted8B:" + TheLastEncrypted8B);
            guess = guess.concat(TheLastEncrypted8B);
            // System.out.printf("guess:%s, len=%d\n", guess, guess.length());
            byte[] ans = null;
            try {
                // System.out.println("after reverse:" + Arrays.toString(reverse) + ",len=" +
                // reverse.length);
                ans = crack.JavaDecrypt(guess);
            } catch (UnsupportedEncodingException e) {
                continue;
            } catch (BadPaddingException e2) {
                continue;
            }
            if (ans != null) {
                boolean flag = true;
                for (int idx = 0; idx < ans.length; idx++) {
                    if (ans[idx] < 32 || ans[idx] > 126) {
                        flag = false;
                        break;
                    }
                    // System.out.printf("[]%x,%d,idx=%d,%s\n", ans[idx], ans[idx], idx, flag);
                }
                if (flag) {
                    outf.write(guess.getBytes(), 0, guess.length());
                    outf.write(ans, 0, ans.length);
                    System.out.printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
                    System.out.println("guess:" + guess + ",len=" + guess.length());
                    System.out.println("decrypt:" + Arrays.toString(ans) + ",len=" + ans.length);
                    String ans_str = new String(ans);
                    System.out.println("decrypt:" + ans_str + ",len=" + ans_str.length());
                    System.out.printf("\n\n");
                    outf.close();
                    return;
                }
            }
        }

        // String flag = "flag{A!k00000000"; // 0CDB3008BCF48850F43B9CD9AA59B84B
        // encrypted = crack.JavaEncrypt(flag); // flag 前半部分确定是 flag{A!k len=8
        // System.out.printf("encrypted: %s, len=%d, flag len=%d\n", encrypted,
        // encrypted.length(), flag.length());
        // System.out.printf("[flag] %s, len=%d\n", Arrays.toString(flag.getBytes()),
        // flag.getBytes().length);
        // // encrypted: len=32, flag len=8~15; flag len=7
        // // encrypted: 0CDB3008BCF48850 F43B9CD9AA59B84B, len=32, flag len=8
        // // 期望最后的结果是 0CDB3008BCF48850 A8A07877
        // // 0CDB3008BCF48850 F43B9CD9AA59B84B
        // String flag_part1 = "flag{A!k";

        // while (true) {
        // String randStr = "";
        // for (int i = 0; i < 8; i++) {
        // randStr = randStr + (char) (rd.nextInt(127 - 32) + 32);
        // // System.out.printf("randStr:%s, len=%d, i=%d\n", randStr, randStr.length(),
        // // i);
        // }
        // String guess = flag_part1.concat(randStr);
        // // System.out.printf("[guess] %s, len=%d\n", guess, guess.length());

        // encrypted = crack.JavaEncrypt(guess);
        // String en_sub = encrypted.substring(16, 16 + 8);
        // // System.out.printf("[encrypted] sub %s\n", en_sub);
        // if (en_sub.equals("A8A07877")) {
        // System.out.printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
        // System.out.printf("[guess] %s, len=%d\n", guess, guess.length());
        // System.out.printf("[encrypted] sub %s\n", en_sub);
        // System.out.printf("[encrypted] %s, len=%d\n", encrypted, encrypted.length());
        // return;
        // }
        // }
    }
}
