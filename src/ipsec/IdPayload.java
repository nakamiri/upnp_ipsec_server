package ipsec;

import java.nio.ByteBuffer;

import encrypt.BinaryHexConverter;

public class IdPayload extends Payload {

	/** 8bit */
	private int next_payload;
	private byte[] reserved = new byte[1];
	private short payload_length;
	
	/** 8bit */
	private int id_type;
	/** 8bit */
	private int protocol_id;
	private short port;
	
	byte[] id_data;
	
	public IdPayload () {
		payload_type = Payload.ID_PAYLOAD;
		
		next_payload = Payload.HASH_PAYLOAD;
		
		long id = (int) (Math.random() * Long.MAX_VALUE);
		id_data = BinaryHexConverter.HexStringToBytes(Long.toHexString(id));
		
		payload_length = 16;
		
		id_type = 0;
		protocol_id = 0;
		port = 0;
	}
	
	public IdPayload (byte[] payload_byte) {
		payload_type = Payload.ID_PAYLOAD;
		
		ByteBuffer bw = ByteBuffer.wrap(payload_byte);

		next_payload = bw.get();
		bw.get(reserved);
		payload_length = bw.getShort();

		id_type = bw.get();
		protocol_id = bw.get();
		port = bw.getShort();
		
		id_data = new byte[payload_length - 8];
		bw.get(id_data);

		left_data = new byte[bw.capacity() - bw.position()];
		bw.get(left_data);
	}
	
	public byte[] getByteArray () {
		ByteBuffer bw = ByteBuffer.allocate(payload_length);
		
		bw.put((byte) next_payload);
		bw.put(reserved);
		bw.putShort(payload_length);
		
		bw.put((byte) id_type);
		bw.put((byte) protocol_id);
		bw.putShort(port);
		
		bw.put(id_data);
		
		return bw.array();
	}
	
	@Override
	public void outputValue() {
		System.out.println("----- ID Payload -----");
		System.out.println("next payload: " + next_payload);
		System.out.println("payload length: " + payload_length);
		System.out.println("ID type: " + id_type);
		System.out.println("protocol id: " + protocol_id);
		System.out.println("Port: " + port);
		System.out.println("ID Data: " + BinaryHexConverter.bytesToHexString(id_data));
		System.out.println("----- ID Payload End -----");
	}

	@Override
	int getNext_payload() {
		return next_payload;
	}

	@Override
	byte[] getLeft_data() {
		return left_data;
	}

	public short getPayload_length() {
		return payload_length;
	}

	public void setNext_payload(int next_payload) {
		this.next_payload = next_payload;
	}

}
