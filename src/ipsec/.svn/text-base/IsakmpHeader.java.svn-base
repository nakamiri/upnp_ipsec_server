package ipsec;

import java.io.IOException;
import java.net.DatagramPacket;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Vector;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import encrypt.BinaryHexConverter;
import encrypt.ByteArrayBits;
import encrypt.EncryptManager;
import encrypt.KeyManager;

public class IsakmpHeader {
	public static final int HEADER_SIZE = 28;
	
	public static final int INIT = 0;
	public static final int RESP = 1;
	
	private DatagramPacket pkt;

	private byte[] isakmp_byte = new byte[HEADER_SIZE];
	private byte[] payload_byte;
	
	private SaPayload sa_payload;
	private KeyExchangePayload key_payload;
	
	private Vector<VendorIdPayload> vendor_id;
	
	private Vector<Payload> payloads;
	
	/** 64bit 16進数文字列 */
//	private String init_cookie;	// 64bit
	private byte[] init_cookie = new byte[8];
	/** 64bit 16進数文字列 */
//	private String resp_cookie;	// 64bit
	private byte[] resp_cookie = new byte[8];
	
	/** 8bit */
	private int next_payload;	// 8bit
	/** 4bit */
	private int major_ver;		// 4bit
	/** 4bit */
	private int minor_ver;		// 4bit
	/** 8bit */
	private byte exchange_type;	// 8bit
	/** 8bit */
	private byte flag;			// 8bit
	
	/** 32bit */
	private int message_id;		// 32bit
	
	/** 32bit */
	private int message_length;	// 32bit
	
	public IsakmpHeader() {
		vendor_id = new Vector<VendorIdPayload>();
	}
	
	/**
	 * パケット受信時のコンストラクタ
	 * @param byte_array ISAKMPヘッダーからのByteAry
	 */
	public IsakmpHeader(byte[] byte_array) {
		payloads = new Vector<Payload>();
		
		// ISAKMPヘッダーのByteAry取得
		for (int i = 0; i < HEADER_SIZE; i++) {
			isakmp_byte[i] = byte_array[i];
		}
		
		// ISAKMP PayloadのByteAry取得
		payload_byte = new byte[1024];
		for (int i = HEADER_SIZE; i < byte_array.length; i++) {
			payload_byte[i-HEADER_SIZE] = byte_array[i];
		}
		
		// Byteをローカル変数に変換
		convertToHeader();
		outputIsakmpHeader();
		
		// 暗号化されているかどうかチェック
		if (flag == 0x01) {
			
		}
		
		// 次ペイロード番号によってペイロード生成振り分け
		Payload payl = Payload.makePayload(next_payload, payload_byte);
		if (next_payload == 1) {
			sa_payload = (SaPayload) payl;
		} else if (next_payload == 4) {
			key_payload = (KeyExchangePayload) payl;
		} else {
			payloads.add(payl);
			payl.outputValue();
		}
		
		while (payl.getNext_payload() != Payload.NONE) {
			payl = Payload.makePayload(payl.getNext_payload(), payl.getLeft_data());
			payloads.add(payl);
			payl.outputValue();
		}
				
	}
	
	public IsakmpHeader (byte[] byte_array, KeyManager key, EncryptManager decode) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException {
		payloads = new Vector<Payload>();
		
		// ISAKMPヘッダーのByteAry取得
		for (int i = 0; i < HEADER_SIZE; i++) {
			isakmp_byte[i] = byte_array[i];
		}
		
		// Byteをローカル変数に変換
		convertToHeader();
		outputIsakmpHeader();
		
		// ISAKMP PayloadのByteAry取得
		payload_byte = new byte[message_length - HEADER_SIZE];
		for (int i = HEADER_SIZE; i < message_length; i++) {
			payload_byte[i-HEADER_SIZE] = byte_array[i];
		}
		
		
		// 暗号化されているかどうかチェック
		if (flag == 0x01) {
			System.out.println("init: " + BinaryHexConverter.bytesToHexString(key.getNonce_init()));
			System.out.println("resp: " + BinaryHexConverter.bytesToHexString(key.getNonce_resp()));
			payload_byte = decode.decode(payload_byte);
//			switch (sender) {
//			case INIT:
//				payload_byte = EncryptManager.init_decode(payload_byte, key.getSkeyid_e(), key.getNonce_init());
//				break;
//			case RESP:
//				payload_byte = EncryptManager.init_decode(payload_byte, key.getSkeyid_e(), key.getNonce_resp());
//			}
		}
		
		// 次ペイロード番号によってペイロード生成振り分け
		Payload payl = Payload.makePayload(next_payload, payload_byte);
		if (next_payload == 1) {
			sa_payload = (SaPayload) payl;
		} else if (next_payload == 4) {
			key_payload = (KeyExchangePayload) payl;
		} else {
			payloads.add(payl);
			payl.outputValue();
		}
		
		while (payl.getNext_payload() != Payload.NONE) {
			payl = Payload.makePayload(payl.getNext_payload(), payl.getLeft_data());
			payloads.add(payl);
			payl.outputValue();
		}
	}
	
	public KeyExchangePayload getKey_payload() {
		return key_payload;
	}

	IsakmpHeader(DatagramPacket pkt) {
		this.pkt = pkt;
		byte[] tmp = pkt.getData();
		for (int i = 0; i < HEADER_SIZE; i++) {
			isakmp_byte[i] = tmp[i];
		}
		
		payload_byte = new byte[1024];
		for (int i = HEADER_SIZE; i < tmp.length; i++) {
			payload_byte[i-HEADER_SIZE] = tmp[i];
		}
	}
	
	public void convertToHeader() {
		ByteBuffer wb = ByteBuffer.wrap(isakmp_byte);

//		init_cookie = wb.getLong();
//		resp_cookie = wb.getLong();
//		byte[] tmp = new byte[8];
//		wb.get(tmp);
//		init_cookie = BinaryHexConverter.bytesToHexString(tmp);
//		wb.get(tmp);
//		resp_cookie = BinaryHexConverter.bytesToHexString(tmp);
		
		wb.get(init_cookie);
		wb.get(resp_cookie);
		
		next_payload = wb.get();
		byte[] ver = new byte[1];
		wb.get(ver);
		ByteArrayBits bab = new ByteArrayBits(ver);
		major_ver = bab.subbits(0, 4);
		minor_ver = bab.subbits(4, 8);
		exchange_type = wb.get();
		flag = wb.get();
		
		message_id = wb.getInt();
		
		message_length = wb.getInt();
	}
	
	public void initClientSaPkt (byte[] init_cookie) {
		this.init_cookie = init_cookie;
		
		next_payload = 1;
		major_ver = 1;
		minor_ver = 0;
		
		exchange_type = 2;
		
		flag = 0;
		
		message_id = 0;
	}
	
	public void initSrvEncryptPkt (byte[] init_cookie, byte[] resp_cookie) {
		this.init_cookie = init_cookie;
		this.resp_cookie = resp_cookie;
		
		next_payload = 5;
		major_ver = 1;
		minor_ver = 0;
		
		exchange_type = 2;
		
		flag = 0x01;
		
		message_id = 0;
	}
	
	public void initClientEncryptPkt (byte[] init_cookie, byte[] resp_cookie) {
		this.init_cookie = init_cookie;
		this.resp_cookie = resp_cookie;
		
		next_payload = Payload.HASH_PAYLOAD;
		major_ver = 1;
		minor_ver = 0;
		
		exchange_type = 2;
		
		flag = 0x01;
		
		message_id = 0;
	}
	
	public void initClientKeyPkt (byte[] init_cookie, byte[] resp_cookie) {
		this.init_cookie = init_cookie;
		this.resp_cookie = resp_cookie;
		
		next_payload = 4;
		major_ver = 1;
		minor_ver = 0;
		
		exchange_type = 2;
		
		flag = 0;
		
		message_id = 0;
	}
	
	public void initSrvSaPkt (IsakmpHeader receiveHeader, byte[] res_cookie) {
		init_cookie = receiveHeader.init_cookie;
		resp_cookie = res_cookie;
		
		next_payload = receiveHeader.getNext_payload();
		major_ver = 1;
		minor_ver = 0;
		
		exchange_type = receiveHeader.exchange_type;
		flag = 0;
		
		message_id = 0;
	}
	
	public TransformPayload getTransformPayload (TypeValue[] values) {
		return sa_payload.getTransformPayload(values);
	}
	
	public Vector<Payload> getPayload (int type) {
		Vector<Payload> p = new Vector<Payload>();
		for (int i = 0; i < payloads.size(); i++) {
			Payload tmp = payloads.elementAt(i);
			if (tmp.payload_type == type) {
				p.add(tmp);
			}
		}
		
		return p;
	}
	
	public void setPayload (SaPayload sph, VendorIdPayload vip) {
		sa_payload = sph;
		vendor_id.add(vip);
		
		message_length = sph.getPayload_length() + vip.getPayload_length() + HEADER_SIZE;
	}
	
	public byte[] getByteArray () {
		byte[] byte_array = new byte[HEADER_SIZE];
		ByteBuffer bw = ByteBuffer.wrap(byte_array);
//		byte[] init_cookie_byte = BinaryHexConverter.HexStringToBytes(init_cookie);
//		bw.put(init_cookie_byte);
		bw.put(init_cookie);
		
//		byte[] resp_cookie_byte = BinaryHexConverter.HexStringToBytes(resp_cookie);
//		bw.put(resp_cookie_byte);
		bw.put(resp_cookie);
		
		bw.put((byte) next_payload);
		
		byte tmp_major = (byte) major_ver; 
		tmp_major <<= 4;
		byte tmp_minor = (byte) minor_ver;
		
		byte ver = (byte) (tmp_major + tmp_minor);
		bw.put(ver);
		
		bw.put((byte) exchange_type);
		
		bw.put((byte) flag);
		
		bw.putInt(message_id);
		bw.putInt(message_length);
		
		return byte_array;
	}
	
	public DatagramPacket getPkt() {
		return pkt;
	}

	public void setPkt(DatagramPacket pkt) {
		this.pkt = pkt;
	}

	public void outputIsakmpHeader() {
		System.out.println("------ ISAKMP Packet Header ------");
		System.out.println("init_cookie: " + BinaryHexConverter.bytesToHexString(init_cookie));
		System.out.println("resp_cookie: " + BinaryHexConverter.bytesToHexString(resp_cookie));
		
		System.out.println("next_payload: " + next_payload);
		System.out.println("major_ver: " + major_ver);
		System.out.println("minor_ver: " + minor_ver);
		System.out.println("exchange_type: " + exchange_type);
		System.out.println("flag: " + flag);
		
		System.out.println("message_id: " + message_id);
		
		System.out.println("message_length: " + message_length);
		System.out.println("------ ISAKMP Header End ------");
	}
	
	public static void outputIsakmpHeader (byte[] header_byte) {
		ByteBuffer wb = ByteBuffer.wrap(header_byte);

		byte[] tmp = new byte[8];
		wb.get(tmp);
		String init_cookie = BinaryHexConverter.bytesToHexString(tmp);
		wb.get(tmp);
		String resp_cookie = BinaryHexConverter.bytesToHexString(tmp);
		
		int next_payload = wb.get();
		byte[] ver = new byte[1];
		wb.get(ver);
		ByteArrayBits bab = new ByteArrayBits(ver);
		int major_ver = bab.subbits(0, 4);
		int minor_ver = bab.subbits(4, 8);
		int exchange_type = wb.get();
		int flag = wb.get();
		
		int message_id = wb.getInt();
		
		int message_length = wb.getInt();
		
		System.out.println("------ ISAKMP Packet Header ------");
		System.out.println("init_cookie: " + init_cookie);
		System.out.println("resp_cookie: " + resp_cookie);
		
		System.out.println("next_payload: " + next_payload);
		System.out.println("major_ver: " + major_ver);
		System.out.println("minor_ver: " + minor_ver);
		System.out.println("exchange_type: " + exchange_type);
		System.out.println("flag: " + flag);
		
		System.out.println("message_id: " + message_id);
		
		System.out.println("message_length: " + message_length);
		System.out.println("------ ISAKMP Header End ------");
	}

	public int getNext_payload() {
		return next_payload;
	}

	public void setNext_payload(int next_payload) {
		this.next_payload = next_payload;
	}

	public int getMessage_length() {
		return message_length;
	}

	public void setMessage_length(int message_length) {
		this.message_length = message_length;
	}

	public byte[] getInit_cookie() {
		return init_cookie;
	}

	public byte[] getResp_cookie() {
		return resp_cookie;
	}
	
	public void setExchange_type(int exchange_type) {
		this.exchange_type = (byte) exchange_type;
	}

	public int getMessage_id() {
		return message_id;
	}

	public void setMessage_id(int message_id) {
		this.message_id = message_id;
	}
	
//	public String getInit_cookie() {
//		return init_cookie;
//	}
//
//	public String getResp_cookie() {
//		return resp_cookie;
//	}
}