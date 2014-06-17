package ipsec;

import java.nio.ByteBuffer;

public class SaPayload extends Payload {
	public static final int SIT_IDENTITY_ONLY = 1;

	private PropPayload prop_payload;
	
	/** 次ペイロード番号 8bit */
	private short next_payload;
	/** 予約 8bit */
	private byte[] reserved = new byte[1];
	/** ペイロード長 16bit */
	private short payload_length;
	
	/** DOI 32bit */
	private int doi;
	
	/** シチュエーション 32bit */
	private int situation;
	
	public SaPayload () {
		payload_type = Payload.SA_PAYLOAD;
		
	}
	
	public SaPayload(byte[] sapayload_byte) {
		payload_type = Payload.SA_PAYLOAD;
		
		ByteBuffer bw = ByteBuffer.wrap(sapayload_byte);
		
		next_payload = bw.get();
		bw.get(reserved);
		payload_length = bw.getShort();
		
		doi = bw.getInt();
		
		situation = bw.getInt();

		outputSaPayloadHeader();
		
		byte[] payload_byte = new byte[payload_length - 12]; 
		bw.get(payload_byte);
		
		prop_payload = new PropPayload(payload_byte);

		left_data = new byte[sapayload_byte.length - payload_length];
		bw.get(left_data);
	}
	
	public void initClientSaPkt () {
		next_payload = 13;
		payload_length = 60;
		doi = 1;
		situation = 1;
	}
	
	public void initSrvSaPkt () {
		next_payload = 13;
		payload_length = 60;
		doi = 1;
		situation = 1;
	}
	
	public void setPropPayloadHeader (PropPayload pph) {
		prop_payload = pph;
		payload_length = (short) (12 + pph.getPayload_length());
	}
	
	public byte[] getByteArray () {
		byte[] send_byte = new byte[12];
		ByteBuffer bw = ByteBuffer.wrap(send_byte);
		
		bw.put((byte) next_payload);
		bw.put(reserved);
		bw.putShort(payload_length);
		
		bw.putInt(doi);
		
		bw.putInt(situation);
		
		return send_byte;
	}
	
	public TransformPayload getTransformPayload (TypeValue[] values) {
		return prop_payload.getTransformPayload(values);
	}
	
	public void outputSaPayloadHeader() {
		System.out.println("----- SA Payload Header -----");
		System.out.println("next_payload: "+next_payload);
		System.out.println("payload_length: "+payload_length);
		System.out.println("doi: "+doi);
		System.out.println("situation: "+situation);
		System.out.println("----- SA Payload End -----");
	}
	
	public static void outputSaPayload (byte[] sapayload_byte) {
		ByteBuffer bw = ByteBuffer.wrap(sapayload_byte);
		
		short next_payload = bw.get();
		bw.get(new byte[1]);
		short payload_length = bw.getShort();
		
		int doi = bw.getInt();
		
		int situation = bw.getInt();
		
		System.out.println("----- SA Payload Header -----");
		System.out.println("next_payload: "+next_payload);
		System.out.println("payload_length: "+payload_length);
		System.out.println("doi: "+doi);
		System.out.println("situation: "+situation);
		System.out.println("----- SA Payload End -----");
	}

	public int getPayload_length() {
		return payload_length;
	}

	@Override
	void outputValue() {
		outputSaPayloadHeader();
	}

	@Override
	int getNext_payload() {
		return next_payload;
	}

	@Override
	byte[] getLeft_data() {
		return left_data;
	}

	public void setNext_payload(short next_payload) {
		this.next_payload = next_payload;
	}

	public int getSituation() {
		return situation;
	}

	public void setSituation(int situation) {
		this.situation = situation;
	}
}