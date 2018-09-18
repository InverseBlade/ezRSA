package ezrsa;

import java.math.*;
import java.nio.ByteBuffer;
import java.util.*;
import java.io.*;

/**
 * 
 * @author 张泽威
 *
 */

public class EzRsa {
    // 密钥位数
    private int keySize;

    // 质数对
    private BigInteger p, q;

    // 质数之积
    private BigInteger n;

    // 欧拉函数
    private BigInteger t;

    // 公钥
    private BigInteger e = new BigInteger("65537", 10); // 公钥值默认=65537

    // 私钥
    private BigInteger d;

    private boolean ifGenerated = false;

    public EzRsa() {
        p = q = n = t = d = null;
    }

    /**
     * 生成密钥对.
     * 
     * @param keySize 密钥比特位长度
     * @throws RsaException
     */
    public void generateKey(int keySize) throws RsaException {
        // 获得keySize位的随机素数
//		p = new BigInteger(
//				"120392186707224917072298986663224305747590713652542594743098609944540538295785065429277507623335343908019518083306720462301223672449891661307886390148706706471093398488552144667307558751313827562251332666471328537831517877391095129483973096836698175203298913553687807802323429820123342252775402158063451040509");
//		q = new BigInteger(
//				"106697219132480173106064317148705638676529121742557567770857687729397446898790451577487723991083173010242416863238099716044775658681981821407922722052778958942891831033512463262741053961681512908218003840408526915629689432111480588966800949428079015682624591636010678691927285321708935076221951173426894836169");
        p = getPrime(keySize);
        q = getPrime(keySize);
        //
        n = p.multiply(q);
        t = (p.subtract(new BigInteger("1"))).multiply(q.subtract(new BigInteger("1")));
        // 扩展欧几里得算法求私钥d
        BigInteger val[] = this.extGcd(e, t);
        this.d = val[0];
        // e的负乘法逆元私钥d转正
        BigInteger _zero = BigInteger.ZERO;
        while (d.compareTo(_zero) < 0)
            d = d.add(t);
        //
        this.keySize = keySize;
        this.ifGenerated = true;
    }

    /**
     * 扩展欧几里得法 求ax+by=1的整数解.
     * 
     * @param a
     * @param b
     * @return
     */
    protected BigInteger[] extGcd(BigInteger a, BigInteger b) {
        //
        if (b.intValue() == 0)
            return new BigInteger[] { new BigInteger("1"), new BigInteger("0") };
        //
        BigInteger val[] = extGcd(b, a.mod(b));
        return new BigInteger[] { val[1], val[0].subtract(a.divide(b).multiply(val[1])) };
    }

    /**
     * Returns a generated public key.
     * 
     * @return
     * @throws RsaException
     */
    public Key getPublicKey() throws RsaException {
        //
        if (!ifGenerated)
            throw new RsaException("key hasn't been generated yet");
        //
        Key key = new Key();
        key.n = n;
        key.keyPair = e;
        return key;
    }

    /**
     * Returns a generated private key.
     * 
     * @return
     * @throws RsaException
     */
    public Key getPrivateKey() throws RsaException {
        //
        if (!this.ifGenerated)
            throw new RsaException("key hasn't been generated yet");
        //
        Key key = new Key();
        key.n = this.n;
        key.keyPair = this.d;
        return key;
    }

    /**
     * Encrypt a string.
     * 
     * @param m
     * @param publicKey
     * @return
     * @throws RsaException
     */
    public String encrypt(String m, Key publicKey) throws RsaException {
        try {
            byte[] _bits = m.getBytes("UTF-8");
            _bits = Base64.getEncoder().encode(_bits);
            BigInteger _m = new BigInteger(_bits);
            BigInteger _tmp;

            if (_m.compareTo(publicKey.n) > 0)
                throw new RsaException("明文长度过大，无法加密!");
            // 模幂运算
            _tmp = modPow(_m, publicKey.keyPair, publicKey.n);

            return _tmp.toString(36);
            //
        } catch (Exception e) {
            throw new RsaException(e.getMessage());
        }
    }

    /**
     * Decrypt a string.
     * 
     * @param c
     * @param privateKey
     * @return
     * @throws RsaException
     */
    public String decrypt(String c, Key privateKey) throws RsaException {
        try {
            BigInteger _c = new BigInteger(c, 36);
            BigInteger _tmp;

            if (_c.compareTo(privateKey.n) > 0)
                throw new RsaException("明文长度过大，无法加密!");
            // 模幂运算
            _tmp = modPow(_c, privateKey.keyPair, privateKey.n);
            byte[] _bits = Base64.getDecoder().decode(_tmp.toByteArray());

            return new String(_bits, "UTF-8");
            //
        } catch (Exception e) {
            throw new RsaException(e.getMessage());
        }
    }

    /**
     * Returns an encrypted string.
     * 
     * @param m
     * @param publicKeyString
     * @return
     * @throws RsaException
     */
    public String encrypt(String m, String publicKeyString) throws RsaException {
        //
        return this.encrypt(m, getKeyByString(publicKeyString));
    }

    /**
     * Returns a decrypted string.
     * 
     * @param c
     * @param privateKeyString
     * @return
     * @throws RsaException
     */
    public String decrypt(String c, String privateKeyString) throws RsaException {
        //
        return this.decrypt(c, getKeyByString(privateKeyString));
    }

    /**
     * Returns an encrypted long string.
     * 
     * @param m
     * @param publicKeyString
     * @return
     * @throws RsaException
     */
    public String encryptLongString(String m, String publicKeyString) throws RsaException {
        //
        return this.encryptLongString(m, getKeyByString(publicKeyString));
    }

    /**
     * Returns a decrypted long string.
     * 
     * @param c
     * @param privateKeyString
     * @return
     * @throws RsaException
     */
    public String decryptLongString(String c, String privateKeyString) throws RsaException {
        //
        return this.decryptLongString(c, getKeyByString(privateKeyString));
    }

    /**
     * Encrypt a long string.
     * 
     * @param m         明文
     * @param publicKey 公钥字符串
     * @return String
     * @throws RsaException
     */
    public String encryptLongString(String m, Key publicKey) throws RsaException {
        try {
            String c = "";
            int blockSz;
            byte[] cBits;
            ByteBuffer byteBf;

            blockSz = publicKey.n.bitLength() / 8 - 1;
            cBits = Base64.getEncoder().encode(m.getBytes("UTF-8"));
            byteBf = ByteBuffer.wrap(cBits);

            byte[] bytes;
            while (byteBf.hasRemaining()) {
                //
                blockSz = byteBf.remaining() <= blockSz ? byteBf.remaining() : blockSz;
                bytes = new byte[blockSz];
                byteBf.get(bytes, 0, bytes.length);
                //
                BigInteger bigNum = new BigInteger(bytes);
                bigNum = this.modPow(bigNum, publicKey.keyPair, publicKey.n);
                c += bigNum.toString(36) + "/";
            }

            return c;
            //
        } catch (Exception e) {
            throw new RsaException(e.getMessage());
        }
    }

    /**
     * Decrypt a long string.
     * 
     * @param c          密文
     * @param privateKey 私钥
     * @return String 明文
     * @throws RsaException
     */
    public String decryptLongString(String c, Key privateKey) throws RsaException {
        try {
            String m = "";
            String cArr[];
            byte[] sumBits = new byte[0];
            int p;

            cArr = c.split("[/]");
            //
            for (int i = 0; i < cArr.length; i++) {
                //
                if (cArr[i].trim().isEmpty()) {
                    continue;
                }
                BigInteger tmp = new BigInteger(cArr[i], 36);
                tmp = this.modPow(tmp, privateKey.keyPair, privateKey.n);
                byte[] bits = tmp.toByteArray();
                // 连接数组
                p = sumBits.length;
                byte[] backUp = new byte[sumBits.length + bits.length];
                System.arraycopy(sumBits, 0, backUp, 0, sumBits.length);
                System.arraycopy(bits, 0, backUp, p, bits.length);
                sumBits = backUp;
            }
            sumBits = Base64.getDecoder().decode(sumBits);
            m = new String(sumBits, "UTF-8");

            return m;
            //
        } catch (Exception e) {
            throw new RsaException(e.getMessage());
        }
    }

    /**
     * 快速模幂运算.
     * 
     * @param base
     * @param exponent
     * @param m
     * @return
     */
    protected BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger m) {
        //
        BigInteger sum = BigInteger.ONE;
        base = base.mod(m);

        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            if (exponent.testBit(0)) {
                sum = sum.multiply(base).mod(m);
            }
            exponent = exponent.shiftRight(1);
            base = base.multiply(base).mod(m);
        }

        return sum;
    }

    /**
     * Returns a key transformed from keyString.
     * 
     * @param keyString 密钥串
     * @return Key 密钥
     * @throws RsaException
     */
    protected Key getKeyByString(String keyString) throws RsaException {
        String val[] = keyString.split("[+]");
        Key key = new Key();

        if (val.length != 2)
            throw new RsaException("Wrong PublicKeyString!");

        key.keyPair = new BigInteger(val[1], 36);
        key.n = new BigInteger(val[0], 36);
        //
        return key;
    }

    /**
     * Returns a huge prime randomly.
     * 
     * @param bitLength 素數位長度
     * @return BigInteger
     */
    protected BigInteger getPrime(int bitLength) throws RsaException {
        //
        BigInteger big = null;

        if (bitLength <= 0)
            throw new RsaException("the bit length of prime cannot be zero");

        for (;;) {
            big = BigInteger.probablePrime(bitLength, new Random());
            if (big.isProbablePrime(1))
                break;
        }

        return big;
    }

}
