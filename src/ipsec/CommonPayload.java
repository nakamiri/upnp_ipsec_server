package ipsec;

import java.nio.ByteBuffer;

public abstract class CommonPayload extends Payload {

	/** 8bit */
	protected int next_payload;
	protected byte[] reserved = new byte[1];
	/** 16bit */
	protected short payload_length;
	
	/** 可変長 */
	protected byte[] data;
	
	public CommonPayload () {
	
	}
	
	public CommonPayload (byte[] payload_byte) {
		ByteBuffer bw = ByteBuffer.wrap(payload_byte);

		next_payload = bw.get();
		bw.get(reserved);
		payload_length = bw.getShort();

		data = new byte[payload_length - 4];
		bw.get(data);

		left_data = new byte[bw.capacity() - bw.position()];
		bw.get(left_data);
	}
	
	public byte[] getByteArray() {
		byte[] send_byte = new byte[1 + 1 + 2 + data.length];
		payload_length = (short) send_byte.length;
		
		ByteBuffer bw = ByteBuffer.wrap(send_byte);
		
		bw.put((byte) next_payload);
		bw.put(reserved);
		bw.putShort(payload_length);
		
		bw.put(data);
		
		return send_byte;
	}
	
	@Override
	abstract void outputValue();

	@Override
	public int getNext_payload() {
		return next_payload;
	}

	public void setNext_payload(int next_payload) {
		this.next_payload = next_payload;
	}

	@Override
	public byte[] getLeft_data() {
		return left_data;
	}

	public byte[] getData() {
		return data;
	}

	public void setData(byte[] data) {
		this.data = data;
	}

	public short getPayload_length() {
		return payload_length;
	}
	

}
