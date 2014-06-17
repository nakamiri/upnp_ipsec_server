package ipsec;

import java.math.BigInteger;
import java.util.Random;

import encrypt.BinaryHexConverter;

/**
 * 乱数ペイロード
 * CBCのIVに使われるっぽい
 * @author Nakamiri
 *
 *　大体52Byteの暗号長？だったよ
 * 8バイト以上256バイト以下の長さ
 */
public class NoncePayload extends CommonPayload {

	public NoncePayload () {
		BigInteger rnd = new BigInteger(17*8, new Random());
		while (rnd.bitLength() != 16*8) {
			rnd = new BigInteger(17*8, new Random());
		}
		
		data = BinaryHexConverter.HexStringToBytes(rnd.toString(16));
	}
	
	public NoncePayload(byte[] payload_byte) {
		super(payload_byte);
		
		payload_type = Payload.NONCE_PAYLOAD;
	}
	
	public void outputNoncePayload () {
		System.out.println("----- Nonce Payload -----");
		System.out.println("next payload: " + next_payload);
		System.out.println("payload length: " + payload_length);
		System.out.println("Nonce Data: " + BinaryHexConverter.bytesToHexString(data));
		System.out.println("----- Nonce Payload End -----");
	}

	@Override
	void outputValue() {
		outputNoncePayload();
	}
}
