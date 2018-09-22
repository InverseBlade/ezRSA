package priv;

import ezrsa.*;

import java.util.*;

public class Main {

    private static EzRsa rsa = new EzRsa();

    public static void main(String[] args) {
        // TODO Auto-generated method stub
        try {
            System.out.println("1.生成密钥对\n2.加密明文\n3.解析密文\n请输入选项:");
            int opt;
            Scanner s = new Scanner(System.in);

            opt = s.nextInt();
            s.nextLine();
            switch (opt) {
                case 1:
                    Key pubKey, priKey;
                    rsa.generateKey(1024);
                    pubKey = rsa.getPublicKey();
                    priKey = rsa.getPrivateKey();
                    System.out.println("---------------Public Key----------------\n" + pubKey.getKeyString());
                    System.out.println("---------------Private Key----------------\n" + priKey.getKeyString());
                    break;
                case 2:
                    System.out.println("请输入明文:");
                    String m = s.nextLine();
                    System.out.println("请粘贴公钥:");
                    String pubKeyStr = s.nextLine();
                    System.out.println("密文如下:");
                    System.out.println(rsa.encryptLongString(m, pubKeyStr));
                    break;
                case 3:
                    System.out.println("请输入密文:");
                    String c = s.nextLine();
                    System.out.println("请粘贴私钥:");
                    String priKeyStr = s.nextLine();
                    System.out.println("明文如下:");
                    System.out.println(rsa.decryptLongString(c, priKeyStr));
                    break;
            }

        } catch (RsaException e) {
            System.out.println("密钥不正确!错误信息:");
            System.out.println(e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
