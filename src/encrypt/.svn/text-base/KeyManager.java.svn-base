package encrypt;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class KeyManager {
	public static final String PREKEY = "premoge";
	
	public static final String ALGO = "HmacSHA256";
	
	private byte[] init_cookie;
	private byte[] resp_cookie;
	
	private byte[] nonce_init;
	private byte[] nonce_resp;
	
	private byte[] skeyid;
	private byte[] skeyid_d;
	private byte[] skeyid_a;
	private byte[] skeyid_e;
	
	public KeyManager (byte[] g_xy, byte[] nonce_init, byte[] nonce_resp, byte[] init_cookie, byte[] resp_cookie) throws NoSuchAlgorithmException, InvalidKeyException {
		this.init_cookie = init_cookie;
		this.resp_cookie = resp_cookie;
		
		this.nonce_init = nonce_init;
		this.nonce_resp = nonce_resp;
		
		// SKEYID
		Key key = new SecretKeySpec(PREKEY.getBytes(), ALGO);
		Mac mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		
		ByteBuffer bw = ByteBuffer.allocate(nonce_init.length + nonce_resp.length);
		bw.put(nonce_init);
		bw.put(nonce_resp);
		
		skeyid = mac.doFinal(bw.array());
		
		// SKEYID_d
		key = new SecretKeySpec(skeyid, ALGO);
		mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		
		bw = ByteBuffer.allocate(g_xy.length + init_cookie.length + resp_cookie.length + 1);
		bw.put(g_xy);
		bw.put(init_cookie);
		bw.put(resp_cookie);
		bw.put((byte) 0);
		
		skeyid_d = mac.doFinal(bw.array());
		
		// SKEYID_a
		key = new SecretKeySpec(skeyid, ALGO);
		mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		
		bw = ByteBuffer.allocate(skeyid_d.length + g_xy.length + init_cookie.length + resp_cookie.length + 1);
		bw.put(skeyid_d);
		bw.put(g_xy);
		bw.put(init_cookie);
		bw.put(resp_cookie);
		bw.put((byte) 1);
		
		skeyid_a = mac.doFinal(bw.array());
		
		// SKEYID_e
		key = new SecretKeySpec(skeyid, ALGO);
		mac = Mac.getInstance(key.getAlgorithm());
		mac.init(key);
		
		bw = ByteBuffer.allocate(skeyid_a.length + g_xy.length + init_cookie.length + resp_cookie.length + 1);
		bw.put(skeyid_a);
		bw.put(g_xy);
		bw.put(init_cookie);
		bw.put(resp_cookie);
		bw.put((byte) 2);
		
		skeyid_e = mac.doFinal(bw.array());
		
		// 鍵長が短いから、p180のKaを使って鍵長くする
//		key = new SecretKeySpec(skeyid_e, ALGO);
//		mac = Mac.getInstance(key.getAlgorithm());
//		mac.init(key);
//		
//		bw = ByteBuffer.allocate(1);
//		bw.put((byte) 0);
//		
//		byte[] k1 = mac.doFinal(bw.array());
//		
//		key = new SecretKeySpec(skeyid_e, ALGO);
//		mac = Mac.getInstance(key.getAlgorithm());
//		mac.init(key);
//		
//		byte[] k2 = mac.doFinal(k1);
//		
//		key = new SecretKeySpec(skeyid_e, ALGO);
//		mac = Mac.getInstance(key.getAlgorithm());
//		mac.init(key);
//		
//		byte[] k3 = mac.doFinal(k2);
//		
//		bw = ByteBuffer.allocate(k1.length + k2.length + k3.length);
//		bw.put(k1);
//		bw.put(k2);
//		bw.put(k3);
//		
//		byte[] hoge = new byte[24];
//		bw.rewind();
//		bw.get(hoge);
//		
//		skeyid_e = hoge;
		System.out.println(BinaryHexConverter.bytesToHexString(skeyid_e));
	}

	public byte[] getSkeyid_e() {
		return skeyid_e;
	}

	public byte[] getNonce_init() {
		return nonce_init;
	}

	public byte[] getNonce_resp() {
		return nonce_resp;
	}

	public byte[] getInit_cookie() {
		return init_cookie;
	}

	public byte[] getResp_cookie() {
		return resp_cookie;
	}

	public byte[] getSkeyid() {
		return skeyid;
	}

	public byte[] getSkeyid_d() {
		return skeyid_d;
	}

	public byte[] getSkeyid_a() {
		return skeyid_a;
	}
}











