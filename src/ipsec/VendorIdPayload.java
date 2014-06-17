package ipsec;

import java.nio.ByteBuffer;

import encrypt.BinaryHexConverter;
import encrypt.MD5;

public class VendorIdPayload extends Payload {
	public static final String MS_NT5_ISAKMPOAKLEY = "1e2b516905991c7d7c96fcbfb587e46100000008";
	public static final String NAT_TRAVERSAL = "4a131c81070358455c5728f20e95452f";
	public static final String IETF_NAT_T_IKE_02 = "90cb80913ebb696e086381b5ec427b1f";
	public static final String MICROSOFT_L2TP_IPSEC_CLIENT = "4048b7d56ebce88525e7de7f00d6c2d3";
	
	/** 次ペイロード 8bit */
	private int next_payload;
	/** 予約 8bit */
	private byte[] reserved = new byte[1];
	/** ペイロード長 16bit */
	private short payload_length;
	
	/** VendorID 可変長 */
	byte[] vendor_id;
	
	/**
	 * ペイロード作成用コンストラクタ
	 * length以外は自分で設定しないといけないよ
	 */
	public VendorIdPayload () {
		
	}
	
	/**
	 * 受信パケット分解用コンストラクタ
	 * 受信したパケットのVendor ID部のbyteだけを指定してね
	 * @param vendor_byte VendorID1個のByte
	 */
	public VendorIdPayload (byte[] vendor_byte) {
		ByteBuffer bw = ByteBuffer.wrap(vendor_byte);
		
		next_payload = bw.get();
		bw.get(reserved);
		payload_length = bw.getShort();
		
		vendor_id = new byte[payload_length - 4];
		bw.get(vendor_id);
		
		left_data = new byte[bw.capacity() - bw.position()];
		bw.get(left_data);
		
		outputVendorIdPayload();
	}
	
	/**
	 * 保持されている値の出力
	 */
	public void outputVendorIdPayload () {
		System.out.println("----- Vendor ID Payload -----");
		System.out.println("next_payload: "+next_payload);
		System.out.println("payload_length: "+payload_length);
		String str = BinaryHexConverter.bytesToHexString(vendor_id);
		System.out.print("vendor id: ");
		if (str.equals(MS_NT5_ISAKMPOAKLEY)) {
			System.out.println("MS NT5 ISAKMPOAKLEY");
		} else if (str.equals(NAT_TRAVERSAL)) {
			System.out.println("RFC 3947 Negotiation of NAT-Traversal in the IKE");
		} else if (str.equals(IETF_NAT_T_IKE_02)) {
			System.out.println("draft-ietf-ipsec-nat-t-ike-02");
		} else if (str.equals(MICROSOFT_L2TP_IPSEC_CLIENT)) {
			System.out.println("Microsoft L2TP/IPsec VPN Client");
		} else {
			System.out.println(BinaryHexConverter.bytesToHexString(vendor_id));
		}
		System.out.println("----- Vendor ID End -----");
	}
	
	/**
	 * 指定されたVendorIDのByteArrayの値を出力
	 * @param vendor_byte VendorID 1個のByteArray
	 */
	public static void outputVendorIdPayload (byte[] vendor_byte) {
		ByteBuffer bw = ByteBuffer.wrap(vendor_byte);
		
		int next_payload = bw.get();
		bw.get(new byte[1]);
		short payload_length = bw.getShort();
		
		byte[] vendor_id = new byte[payload_length - 4];
		bw.get(vendor_id);
		
		System.out.println("----- Vendor ID Payload -----");
		System.out.println("next_payload: "+next_payload);
		System.out.println("payload_length: "+payload_length);
		String str = BinaryHexConverter.bytesToHexString(vendor_id);
		System.out.print("vendor id: ");
		if (str.equals(MS_NT5_ISAKMPOAKLEY)) {
			System.out.println("MS NT5 ISAKMPOAKLEY");
		} else if (str.equals(NAT_TRAVERSAL)) {
			System.out.println("RFC 3947 Negotiation of NAT-Traversal in the IKE");
		} else if (str.equals(IETF_NAT_T_IKE_02)) {
			System.out.println("draft-ietf-ipsec-nat-t-ike-02");
		} else if (str.equals(MICROSOFT_L2TP_IPSEC_CLIENT)) {
			System.out.println("Microsoft L2TP/IPsec VPN Client");
		} else {
			System.out.println(BinaryHexConverter.bytesToHexString(vendor_id));
		}
		System.out.println("----- Vendor ID End -----");
	}
	
	/**
	 * VendorIDのByteArrayを取得
	 * @return VendorIDのbyte[]
	 */
	public byte[] getByteArray () {
		byte[] send_byte = new byte[4 + vendor_id.length];
		ByteBuffer bw = ByteBuffer.wrap(send_byte);
		
		bw.put((byte) next_payload);
		bw.put(reserved);
		bw.putShort((short) send_byte.length);
		
		bw.put(vendor_id);
		
		return send_byte;
	}

	public int getNext_payload() {
		return next_payload;
	}

	public void setNext_payload(int next_payload) {
		this.next_payload = next_payload;
	}

	public int getPayload_length() {
		return payload_length;
	}

	public void setPayload_length(short payload_length) {
		this.payload_length = payload_length;
	}

	public byte[] getVendor_id() {
		return vendor_id;
	}

	public void setVendor_id(byte[] vendor_id) {
		this.vendor_id = vendor_id;
		payload_length = (short) (4 + vendor_id.length);
	}

	@Override
	void outputValue() {
		outputVendorIdPayload();
	}

	@Override
	byte[] getLeft_data() {
		return left_data;
	}
}
