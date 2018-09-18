package ezrsa;

import java.math.*;

public class Key {

	protected BigInteger n;

	protected BigInteger keyPair;

	public void printKey() throws RsaException {
		if (n == null || keyPair == null)
			throw new RsaException("n or keyPair in Key cannot be null");
		System.out.println(n.toString(16));
		System.out.println(keyPair.toString(16));
	}

	public String getKeyString() {
		return n.toString(36) + "+" + keyPair.toString(36);
	}

	public void setN(BigInteger n) {
		this.n = n;
	}

	public void setKeyPair(BigInteger keyPair) {
		this.keyPair = keyPair;
	}

}
