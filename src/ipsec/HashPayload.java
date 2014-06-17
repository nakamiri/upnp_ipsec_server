package ipsec;

import java.awt.RenderingHints.Key;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import encrypt.BinaryHexConverter;
import encrypt.KeyManager;

public class HashPayload extends CommonPayload {

	public static final int INIT_HASH = 0;
	public static final int RESP_HASH = 1;
	public static final int QUICK_HASH_1 = 2;
	public static final int QUICK_HASH_2 = 3;
	public static final int QUICK_HASH_3 = 4;
	public static final int QUICK_UPNP = 5;
	
	public HashPayload () {
		payload_type = Payload.HASH_PAYLOAD;
		
		next_payload = Payload.NONE;
	}
	
	public HashPayload (byte[] payload_byte) {
		super(payload_byte);
		
		payload_type = Payload.HASH_PAYLOAD;
	}
		
	/**
	 * ハッシュの計算
	 * @param sa_payload 最初の4バイト（次ペイロード、予約、ペイロード長）を除いたもの
	 * @param id_payload　最初の4バイト（次ペイロード、予約、ペイロード長）を除いたもの
	 * @param key_manager
	 * @param type　定数参照
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 */
	public void calcMainHashValue (byte[] id_payload, KeyManager key_manager, int type) throws NoSuchAlgorithmException, InvalidKeyException {
		SecretKeySpec key = new SecretKeySpec(key_manager.getSkeyid(), KeyManager.ALGO);
		Mac mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		
		int length = key_manager.getNonce_init().length + key_manager.getNonce_resp().length +
						key_manager.getInit_cookie().length + key_manager.getResp_cookie().length +
						id_payload.length;
		
		ByteBuffer bw = ByteBuffer.allocate(length);
		switch (type) {
		case INIT_HASH:
			bw.put(key_manager.getNonce_init());
			bw.put(key_manager.getNonce_resp());
			bw.put(key_manager.getInit_cookie());
			bw.put(key_manager.getResp_cookie());
			bw.put(id_payload);
			break;
		case RESP_HASH:
			bw.put(key_manager.getNonce_resp());
			bw.put(key_manager.getNonce_init());
			bw.put(key_manager.getResp_cookie());
			bw.put(key_manager.getInit_cookie());
			bw.put(id_payload);
			break;
		}
		
		data = mac.doFinal(bw.array());
		
		payload_length = (short) (4 + data.length);
	}
	
	public void calcQuickHashValue (byte[] payload, KeyManager key_manager, byte[] nonce_init, byte[] nonce_resp, int message_id, int type) throws NoSuchAlgorithmException, InvalidKeyException {
		SecretKeySpec key = new SecretKeySpec(key_manager.getSkeyid_a(), KeyManager.ALGO);
		Mac mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		
		int length = 0;
		ByteBuffer bw = null;
		switch (type) {
		case QUICK_HASH_1:
			length = 4 + payload.length;
			bw = ByteBuffer.allocate(length);
			bw.putInt(message_id);
			bw.put(payload);
			
			break;
		case QUICK_HASH_2:
			length = 4 + nonce_init.length + payload.length;
			bw = ByteBuffer.allocate(length);
			bw.putInt(message_id);
			bw.put(nonce_init);
			
			break;
		case QUICK_HASH_3:
			length = 1 + 4 + nonce_init.length + nonce_resp.length;
			bw = ByteBuffer.allocate(length);
			bw.put((byte) 0);
			bw.putInt(message_id);
			bw.put(nonce_init);
			bw.put(nonce_resp);
			
			break;
			
		}
		
		data = mac.doFinal(bw.array());
		
		payload_length = (short) (4 + data.length);
	}
	
	public void outputHashPayload () {
		System.out.println("----- Hash Payload -----");
		System.out.println("next payload: " + next_payload);
		System.out.println("payload length: " + payload_length);
		System.out.println("Hash Data: " + BinaryHexConverter.bytesToHexString(data));
		System.out.println("----- Hash Payload End -----");
	}
	
	@Override
	void outputValue() {
		outputHashPayload();
	}

}
