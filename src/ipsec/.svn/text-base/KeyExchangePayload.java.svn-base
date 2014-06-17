package ipsec;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import encrypt.BinaryHexConverter;

/**
 * 鍵交換ペイロードクラス
 * @author Nakamiri
 *　時々鍵生成するときに260バイトじゃなくて259バイトになることがあるっぽい？
 */
public class KeyExchangePayload extends CommonPayload {

	private String val = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF";
	
	private BigInteger generator;
	private BigInteger secret;
	private BigInteger prime;
	
	public KeyExchangePayload () throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
		prime = new BigInteger(val, 16);
		
		generator = new BigInteger("2");
				
		secret = new BigInteger(prime.bitLength(), new Random());
		
//		BigInteger pow = generator.pow(random.intValue());
		
		BigInteger key_data = generator.modPow(secret, prime);
		
		data = BinaryHexConverter.HexStringToBytes(key_data.toString(16));
	}
	
	public KeyExchangePayload (byte[] payload_byte) {
		super(payload_byte);
		
		payload_type = Payload.KEY_EXCHANGE_PAYLOAD;
		
		outputKeyExchangePayload();
	}
	
	public byte[] calcShareKey (byte[] received_key) {
		String received_str = BinaryHexConverter.bytesToHexString(received_key);
		BigInteger received = new BigInteger(received_str, 16);
		
		BigInteger share_key = received.modPow(secret, prime);
		
		return BinaryHexConverter.HexStringToBytes(share_key.toString(16));
	}
	
	public void outputKeyExchangePayload () {
		System.out.println("----- KeyExchange Paylaod -----");
		System.out.println("Next payload: " + next_payload);
		System.out.println("Payload Length: " + payload_length);
		System.out.println("Key Exchange Data: " + BinaryHexConverter.bytesToHexString(data));
		System.out.println("----- KeyExchange Paylaod End -----");
	}

	@Override
	public void outputValue() {
		outputKeyExchangePayload();
	}

	public BigInteger getRandom() {
		return secret;
	}
}
