package ipsec;

import java.nio.ByteBuffer;
import java.util.Vector;

public class PropPayload {
	/** 2:別のプロポーサルヘッダが存在  0:これで終わり */
	private short next_payload;				// 2 or 0
	private byte[] reserved = new byte[1];
	/** 自身とトランスフォームペイロードを含めた大きさ */
	private short payload_length;				// プロポーザルヘッダを含めた長さ
	
	/** このヘッダの優先度らしいよ */
	private int prop_num;
	/** Phase1だとPROTO_ISAKMP(1) Phase2だとPROTO_IPSEC_AH(2)とか */
	private int protocol_id;
	/** Phase1だと0 Phase2だと4が基本的に入る */
	private int spi_length;
	/** トランスフォームペイロードの数 */
	private int transform_num;
	
	private Vector<TransformPayload> trans_payload;
	
	public PropPayload(byte[] proppayload_byte) {
		ByteBuffer bw = ByteBuffer.wrap(proppayload_byte);
		
		next_payload = bw.get();
		bw.get(reserved);
		payload_length = bw.getShort();
		
		prop_num = bw.get();
		protocol_id = bw.get();
		spi_length = bw.get();
		transform_num = bw.get();
		
		byte[] payload_byte = new byte[payload_length - 8];
		for (int i = 8; i < payload_length; i++) {
			payload_byte[i-8] = proppayload_byte[i];
		}
		
		outputPropPayloadHeader();
		
		trans_payload = new Vector<TransformPayload>();
		for (int i = 0; i < transform_num; i++) {
			trans_payload.add(new TransformPayload(payload_byte));
			int pay_length = trans_payload.get(i).getPayload_length();
			byte[] tmp = payload_byte;
			payload_byte = new byte[tmp.length];
			for (int j = 0; j < tmp.length - pay_length; j++) {
				payload_byte[j] = tmp[j + pay_length];
			}
		}
		
		
	}
	
	public PropPayload() {
		trans_payload = new Vector<TransformPayload>();
	}
	
	public void addTransformPayload (TransformPayload tp) {
		trans_payload.add(tp);
		transform_num = trans_payload.size();
		short length = 8;
		for (int i = 0; i < trans_payload.size(); i++) {
			length += trans_payload.elementAt(i).getPayload_length();
		}
		payload_length = length;
	}
	
	public void initClientSaPkt() {
		next_payload = 0;
		payload_length = 48;
		prop_num = 1;
		protocol_id = 1;
		spi_length = 0;
		transform_num = 1;
	}
	
	public void initSrvSaPkt () {
		next_payload = 0;
		payload_length = 48;
		prop_num = 1;
		protocol_id = 1;
		spi_length = 0;
		transform_num = 1;
	}
	
	public byte[] getByteArray() {
		byte[] send_byte = new byte[8];
		ByteBuffer bw = ByteBuffer.wrap(send_byte);
		
		bw.put((byte) next_payload);
		bw.put(reserved);
		bw.putShort(payload_length);
		
		bw.put((byte) prop_num);
		bw.put((byte) protocol_id);
		bw.put((byte) spi_length);
		bw.put((byte) transform_num);
		
		return send_byte;
	}
	
	/**
	 * 指定された
	 * @param values
	 * @return
	 */
	public TransformPayload getTransformPayload (TypeValue[] values) {
		for (int i = 0; i < trans_payload.size(); i++) {
			TransformPayload tp = trans_payload.elementAt(i);
			if (tp.containValues(values)) {
				return tp;
			}
		}
		return null;
	}
	
	public void outputPropPayloadHeader() {
		System.out.println("----- Proposal Payload Header -----");
		System.out.println("next_payload: "+next_payload);
		System.out.println("payload_length: "+payload_length);
		System.out.println("prop_num: "+prop_num);
		System.out.println("protocol_id: "+protocol_id);
		System.out.println("spi_length: "+spi_length);
		System.out.println("transform_num: "+transform_num);
		System.out.println("----- Proposal Payload End -----");
	}
	
	public static void outputPropPayload (byte[] proppayload_byte) {
		ByteBuffer bw = ByteBuffer.wrap(proppayload_byte);
		
		short next_payload = bw.get();
		bw.get(new byte[1]);
		short payload_length = bw.getShort();
		
		int prop_num = bw.get();
		int protocol_id = bw.get();
		int spi_length = bw.get();
		int transform_num = bw.get();
		
		System.out.println("----- Proposal Payload Header -----");
		System.out.println("next_payload: "+next_payload);
		System.out.println("payload_length: "+payload_length);
		System.out.println("prop_num: "+prop_num);
		System.out.println("protocol_id: "+protocol_id);
		System.out.println("spi_length: "+spi_length);
		System.out.println("transform_num: "+transform_num);
		System.out.println("----- Proposal Payload End -----");
	}

	public short getPayload_length() {
		return payload_length;
	}
}